/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/dump.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>

#include "analyze/policy_db.h"
#include "analyze/report.h"
#include "analyze/rulegen.h"
#include "analyze/type_info.h"
#include "android/control.h"
#include "android/device_info.h"
#include "config.h"
#include "journal.h"
#include "label/labeler.h"

namespace selogger {

namespace {

constexpr char kDefaultOutDir[] = "/data/local/tmp/selogger-dump";

constexpr char kDumpUsage[] =
        "Usage: selogger dump [--out-dir DIR | --stdout | --raw]\n"
        "\n"
        "  --out-dir DIR  write the files to DIR (default /data/local/tmp/selogger-dump)\n"
        "  --stdout       print the files instead, each after a \"==> name <==\" line\n"
        "  --raw          print the collected denials, one per line, and nothing else\n";

struct Options {
    std::string out_dir = kDefaultOutDir;
    bool to_stdout = false;
    bool raw = false;
};

bool ParseOptions(const std::vector<std::string>& args, Options* options) {
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "--out-dir" && i + 1 < args.size()) {
            options->out_dir = args[++i];
        } else if (args[i] == "--stdout") {
            options->to_stdout = true;
        } else if (args[i] == "--raw") {
            options->raw = true;
        } else {
            return false;
        }
    }
    return true;
}

// The platform version CIL names are suffixed with, e.g. "202604".
std::string PlatformVersion() {
    std::string version;
    if (!android::base::ReadFileToString("/vendor/etc/selinux/plat_sepolicy_vers.txt", &version))
        return "";
    return android::base::Trim(version);
}

PolicyDb LoadPolicy() {
    PolicyDb db(PlatformVersion());
    struct CilFile {
        const char* path;
        PolicyOrigin origin;
    };
    const CilFile kFiles[] = {
            {"/system/etc/selinux/plat_sepolicy.cil", PolicyOrigin::kPlatform},
            {"/system_ext/etc/selinux/system_ext_sepolicy.cil", PolicyOrigin::kPlatform},
            {"/product/etc/selinux/product_sepolicy.cil", PolicyOrigin::kPlatform},
            {"/vendor/etc/selinux/vendor_sepolicy.cil", PolicyOrigin::kVendor},
            {"/odm/etc/selinux/odm_sepolicy.cil", PolicyOrigin::kVendor},
    };
    size_t loaded = 0;
    for (const CilFile& file : kFiles) {
        std::string text;
        if (!android::base::ReadFileToString(file.path, &text)) continue;
        db.AddCil(text, file.origin);
        loaded++;
    }
    if (loaded == 0) {
        LOG(WARNING)
                << "No CIL files readable: attributes, private types and genfs labels are unknown";
    }
    return db;
}

uint64_t KernelLost() {
    auto status = SendControlCommand("status");
    if (!status) return 0;
    for (const std::string& line : android::base::Split(*status, "\n")) {
        uint64_t lost;
        if (line.starts_with("kernel_lost: ") && android::base::ParseUint(line.substr(13), &lost))
            return lost;
    }
    return 0;
}

bool WriteFiles(const std::string& out_dir, const std::map<std::string, std::string>& files) {
    std::error_code error;
    // Start from nothing, so files of an earlier dump do not stay behind.
    std::filesystem::remove_all(out_dir, error);
    for (const auto& [name, content] : files) {
        std::filesystem::path path = std::filesystem::path(out_dir) / name;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error) {
            LOG(ERROR) << "Cannot create " << path.parent_path() << ": " << error.message();
            return false;
        }
        if (!android::base::WriteStringToFile(content, path.string())) {
            PLOG(ERROR) << "Cannot write " << path;
            return false;
        }
    }
    return true;
}

}  // namespace

int RunDump(const std::vector<std::string>& args) {
    Options options;
    if (!ParseOptions(args, &options)) {
        fputs(kDumpUsage, stderr);
        return 1;
    }

    Config config = LoadConfig(kDefaultConfigPath);
    // Counters of known denials are written rarely; ask the daemon for what
    // it holds. Without a daemon the journal is all there is.
    SendControlCommand("flush");

    TupleTable table(1000000, 256);
    JournalMeta meta;
    if (!Journal(config.journal_path()).Load(&table, &meta)) {
        fprintf(stderr, "selogger: cannot read %s\n", config.journal_path().c_str());
        return 1;
    }
    std::vector<Tuple> collected;
    for (const auto& [key, tuple] : table.tuples()) collected.push_back(tuple);
    std::sort(collected.begin(), collected.end(),
              [](const Tuple& a, const Tuple& b) { return a.key < b.key; });
    if (collected.empty()) {
        fputs("selogger: nothing has been collected\n", stderr);
        return 1;
    }

    if (options.raw) {
        fputs(FormatTuples(collected).c_str(), stdout);
        return 0;
    }

    PolicyDb policy = LoadPolicy();
    AndroidDeviceInfo device;
    LabelResult labels = RunLabelers(collected, device, &policy);
    PolicyTypes types(&policy, labels.plan.new_types);
    RuleSet rules = GenerateRules(labels.tuples, types, &policy);
    auto files = BuildOutputFiles({collected, labels.plan, rules, KernelLost()});

    if (options.to_stdout) {
        for (const auto& [name, content] : files)
            printf("==> %s <==\n%s\n", name.c_str(), content.c_str());
        return 0;
    }
    if (!WriteFiles(options.out_dir, files)) return 1;
    printf("Wrote %zu files for %zu kinds of denials to %s\nRead %s/REVIEW.md first.\n",
           files.size(), collected.size(), options.out_dir.c_str(), options.out_dir.c_str());
    return 0;
}

}  // namespace selogger
