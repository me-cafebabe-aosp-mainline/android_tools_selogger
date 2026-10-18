/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-base/parseint.h>
#include <android-base/strings.h>

#include <algorithm>
#include <cctype>
#include <optional>

#include "label/labeler.h"

namespace selogger {

namespace {

constexpr size_t kCollapseSiblings = 3;

// Where vendor sepolicy may put file_contexts entries.
const char* const kVendorPrefixes[] = {"/vendor/",
                                       "/odm/",
                                       "/data/vendor/",
                                       "/data/vendor_ce/",
                                       "/data/vendor_de/",
                                       "/mnt/vendor/",
                                       "/dev/",
                                       "/persist/",
                                       "/firmware/",
                                       "/bt_firmware/",
                                       "/dsp/",
                                       "/metadata/vendor/",
                                       "/efs/"};

// Per-app and per-user storage is the platform's business.
const char* const kSkippedPrefixes[] = {"/data/data/",   "/data/user/", "/data/user_de/",
                                        "/storage/",     "/sdcard/",    "/mnt/user/",
                                        "/mnt/runtime/", "/data/app/",  "/data/media/"};

struct PseudoFs {
    const char* fs;
    const char* default_mount;
    const char* attribute;
};
const PseudoFs kPseudoFs[] = {
        {"sysfs", "/sys", "sysfs_type"},
        {"proc", "/proc", "proc_type"},
        {"debugfs", "/sys/kernel/debug", "debugfs_type"},
        {"tracefs", "/sys/kernel/tracing", "tracefs_type"},
        {"configfs", "/config", "configfs_type"},
};

std::string Basename(const std::string& path) {
    size_t slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool StartsWithAny(const std::string& path, const char* const* prefixes, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (path.starts_with(prefixes[i]) || path + "/" == prefixes[i]) return true;
    }
    return false;
}

// "/proc/1234/..." is a different path for every process.
bool IsPerProcessPath(const std::string& path) {
    if (!path.starts_with("/proc/")) return false;
    std::string next = path.substr(
            6, path.find('/', 6) == std::string::npos ? std::string::npos : path.find('/', 6) - 6);
    return next == "self" || next == "thread-self" ||
           (!next.empty() && std::all_of(next.begin(), next.end(), ::isdigit));
}

const PseudoFs* PseudoFsOf(const std::string& path, const std::set<std::string>& devs) {
    for (const PseudoFs& fs : kPseudoFs) {
        if (devs.contains(fs.fs)) return &fs;
    }
    // Most specific mount first.
    for (const char* fs : {"debugfs", "tracefs", "sysfs", "proc", "configfs"}) {
        for (const PseudoFs& candidate : kPseudoFs) {
            if (std::string(candidate.fs) == fs &&
                (path == candidate.default_mount ||
                 path.starts_with(std::string(candidate.default_mount) + "/"))) {
                return &candidate;
            }
        }
    }
    return nullptr;
}

// Directories whose entries are numbered in the order the devices appear,
// so "wakeup14" may be "wakeup9" on the next boot. genfscon matches a
// prefix, so the label goes to the directory above.
bool IsNumberedInstance(const std::string& component) {
    static const char* const kNumbered[] = {"wakeup",       "hwmon",         "event", "input",
                                            "iio:device",   "i2c-",          "mtd",   "gpiochip",
                                            "thermal_zone", "cooling_device"};
    for (const char* prefix : kNumbered) {
        std::string p = prefix;
        if (component.size() > p.size() && component.starts_with(p) &&
            std::all_of(component.begin() + p.size(), component.end(), ::isdigit)) {
            return true;
        }
    }
    return false;
}

// Cuts the path before its first numbered instance; returns whether it did.
bool StripNumberedInstance(std::string* path) {
    size_t start = 1;
    while (start < path->size()) {
        size_t end = path->find('/', start);
        if (end == std::string::npos) end = path->size();
        if (IsNumberedInstance(path->substr(start, end - start))) {
            path->resize(start - 1);
            return true;
        }
        start = end + 1;
    }
    return false;
}

std::vector<std::string> Objects(const Tuple& tuple, const LabelContext& ctx) {
    std::set<std::string> paths;
    if (auto it = tuple.hints.find(kHintPath); it != tuple.hints.end()) {
        for (std::string path : it->second) {
            if (path.ends_with(" (deleted)")) path.resize(path.size() - 10);
            if (path.starts_with("/")) paths.insert(path);
        }
    }
    if (auto it = tuple.hints.find(kHintDevIno); it != tuple.hints.end()) {
        for (const std::string& value : it->second) {
            std::vector<std::string> parts = android::base::Split(value, ":");
            uint64_t ino;
            if (parts.size() < 2 || !android::base::ParseUint(parts[1], &ino)) continue;
            std::string path =
                    ctx.device.ResolveInode(parts[0], ino, parts.size() > 2 ? parts[2] : "");
            if (path.starts_with("/")) paths.insert(path);
        }
    }
    return {paths.begin(), paths.end()};
}

struct Choice {
    std::string type;
    std::string declaration;  // the line for <home>/file.te
    std::set<std::string> attributes;
};

enum class Category { kExec, kDevice, kSocket, kVendorData, kVendorFile, kOtherFile };

Category CategoryOf(const std::string& path, const Tuple& tuple) {
    bool exec = tuple.perms.contains("execute") || tuple.perms.contains("execute_no_trans") ||
                tuple.perms.contains("entrypoint");
    if (path.starts_with("/dev/socket/") || tuple.key.tclass == "sock_file")
        return Category::kSocket;
    if (path.starts_with("/dev/") &&
        (tuple.key.tclass == "chr_file" || tuple.key.tclass == "blk_file")) {
        return Category::kDevice;
    }
    if (exec || path.find("/bin/") != std::string::npos) return Category::kExec;
    if (path.starts_with("/data/vendor") || path.starts_with("/mnt/vendor/") ||
        path.starts_with("/persist/") || path.starts_with("/metadata/vendor/")) {
        return Category::kVendorData;
    }
    if (path.starts_with("/vendor/") || path.starts_with("/odm/")) return Category::kVendorFile;
    return Category::kOtherFile;
}

// What a labeled directory (and everything under it) is for.
Category DirectoryCategoryOf(const std::string& path) {
    if (path.starts_with("/data/vendor") || path.starts_with("/mnt/vendor/") ||
        path.starts_with("/persist") || path.starts_with("/metadata/vendor/")) {
        return Category::kVendorData;
    }
    if (path.starts_with("/vendor/") || path.starts_with("/odm/")) return Category::kVendorFile;
    return Category::kOtherFile;
}

Choice ChooseType(Category category, const std::string& path, const LabelContext& ctx) {
    std::string stem = SanitizeName(Basename(path));
    if (stem.starts_with("android_hardware_")) stem = stem.substr(8);
    Choice c;
    switch (category) {
        case Category::kExec:
            c.type = ctx.FreshTypeName(stem + "_exec");
            c.attributes = {"exec_type", "file_type"};
            if (path.starts_with("/vendor/") || path.starts_with("/odm/"))
                c.attributes.insert("vendor_file_type");
            break;
        case Category::kDevice:
            c.type = ctx.FreshTypeName(stem + "_device");
            c.attributes = {"dev_type"};
            break;
        case Category::kSocket:
            c.type = ctx.FreshTypeName(stem + "_socket");
            c.attributes = {"file_type"};
            break;
        case Category::kVendorData:
            c.type = ctx.FreshTypeName(stem + "_data_file");
            c.attributes = {"file_type", "data_file_type"};
            break;
        case Category::kVendorFile:
            c.type = ctx.FreshTypeName(stem + "_vendor_file");
            c.attributes = {"file_type", "vendor_file_type"};
            break;
        case Category::kOtherFile:
            c.type = ctx.FreshTypeName(stem + "_file");
            c.attributes = {"file_type"};
            break;
    }
    c.declaration = "type " + c.type;
    for (const std::string& attr : c.attributes) c.declaration += ", " + attr;
    c.declaration += ";";
    return c;
}

// file_contexts line for a path or, for a directory, everything below it.
std::string FileContextsLine(const std::string& path, bool directory, const std::string& type) {
    std::string regex = EscapeRegex(path) + (directory ? "(/.*)?" : "");
    return regex + " u:object_r:" + type + ":s0";
}

// Returns whether the object got a proposal (or already has what it needs).
bool LabelPseudoFsPath(const Tuple& tuple, const std::string& path, const PseudoFs& fs,
                       const LabelContext& ctx, std::map<std::string, std::string>* type_of_entry) {
    std::string mount = ctx.device.MountPoint(fs.fs);
    if (mount.empty()) mount = fs.default_mount;
    std::string real = ctx.device.RealPath(path);
    if (!real.starts_with(mount + "/")) real = path;
    std::string rel = real.starts_with(mount + "/") ? real.substr(mount.size()) : real;

    const std::string& domain = tuple.key.stype;
    if (StripNumberedInstance(&rel)) {
        ctx.Note(domain, path + " is numbered in the order devices appear; the label is for " +
                                 rel + " and everything below it");
    }
    if (ctx.policy) {
        if (auto existing = ctx.policy->LookupGenfs(fs.fs, rel);
            existing && !IsGenericFileType(existing->type)) {
            ctx.Note(domain, path + " already has genfscon label " + existing->type +
                                     " but the denial shows " + tuple.key.ttype +
                                     "; the device may be running older policy");
            return false;
        }
    }

    auto known = type_of_entry->find(rel);
    if (known == type_of_entry->end()) {
        // A private platform domain cannot name a vendor type, so what it
        // needs is labeled in the platform's sepolicy.
        bool platform = ctx.IsPlatformDomain(domain);
        std::string home = platform ? "platform" : "vendor";
        std::string type = ctx.FreshTypeName((platform ? "" : "vendor_") + std::string(fs.fs) +
                                             "_" + SanitizeName(Basename(rel)));
        std::set<std::string> attrs = {"fs_type"};
        std::string declaration = "type " + type + ", fs_type";
        if (!ctx.policy || ctx.policy->HasAttributeDefined(fs.attribute)) {
            declaration += std::string(", ") + fs.attribute;
            attrs.insert(fs.attribute);
        }
        ctx.plan->new_types[type] = attrs;
        ctx.plan->AddLine(home + "/file.te", declaration + ";");
        ctx.plan->AddLine(home + "/genfs_contexts", "genfscon " + std::string(fs.fs) + " " + rel +
                                                            " u:object_r:" + type + ":s0");
        known = type_of_entry->emplace(rel, type).first;
    }
    ctx.plan->synthesized.push_back(Retarget(tuple, known->second));
    return true;
}

}  // namespace

void LabelFiles(const std::vector<Tuple>& tuples, const LabelContext& ctx) {
    for (const Tuple& tuple : tuples) {
        if (!IsFileClass(tuple.key.tclass) || !IsGenericFileType(tuple.key.ttype)) continue;
        const std::string& domain = tuple.key.stype;

        if (tuple.perms.contains("create") && tuple.hints.contains(kHintName)) {
            for (const std::string& name : tuple.hints.at(kHintName)) {
                ctx.Note(domain, "creates \"" + name + "\" in a directory labeled " +
                                         tuple.key.ttype +
                                         "; to label what it creates use file_type_auto_trans(" +
                                         domain + ", " + tuple.key.ttype +
                                         ", <new type>) and a file_contexts entry");
            }
        }

        std::set<std::string> devs;
        if (auto it = tuple.hints.find(kHintDevIno); it != tuple.hints.end()) {
            for (const std::string& value : it->second)
                devs.insert(value.substr(0, value.find(':')));
        }

        // Group the objects by the file system kind, since pseudo file
        // systems get genfscon and the rest file_contexts.
        std::vector<std::string> regular;
        std::vector<std::pair<std::string, const PseudoFs*>> pseudo;
        size_t unusable = 0;
        for (const std::string& path : Objects(tuple, ctx)) {
            if (IsPerProcessPath(path) ||
                StartsWithAny(path, kSkippedPrefixes, std::size(kSkippedPrefixes))) {
                unusable++;
                continue;
            }
            if (const PseudoFs* fs = PseudoFsOf(path, devs)) {
                pseudo.emplace_back(path, fs);
            } else {
                regular.push_back(path);
            }
        }
        if (regular.empty() && pseudo.empty()) {
            if (unusable == 0) {
                ctx.Note(domain, "denial on " + tuple.key.ttype + ":" + tuple.key.tclass +
                                         " without a path (" +
                                         android::base::Join(tuple.perms, " ") +
                                         "); the object cannot be labeled from the log");
            }
            continue;
        }

        size_t handled = 0;
        std::map<std::string, std::string> type_of_entry;
        for (const auto& [path, fs] : pseudo) {
            if (LabelPseudoFsPath(tuple, path, *fs, ctx, &type_of_entry)) handled++;
        }

        bool directory = tuple.key.tclass == "dir";
        for (const std::string& entry : CollapseSiblings(regular, kCollapseSiblings)) {
            // A collapsed entry stands for a directory's contents.
            bool is_dir =
                    directory || std::find(regular.begin(), regular.end(), entry) == regular.end();
            std::string existing = ctx.device.FileLabel(entry, is_dir ? "dir" : tuple.key.tclass);
            if (!existing.empty() && !IsGenericFileType(existing)) {
                ctx.Note(domain, entry + " is labeled " + existing +
                                         " by file_contexts but the denial shows " +
                                         tuple.key.ttype +
                                         ": relabel it (restorecon), or fix how it is created");
                continue;
            }
            std::string home = StartsWithAny(entry, kVendorPrefixes, std::size(kVendorPrefixes))
                                       ? "vendor"
                                       : "platform";
            if (home == "platform") {
                ctx.Note(domain, entry + " is outside the paths vendor sepolicy labels; the entry "
                                         "is written "
                                         "for the platform's file_contexts");
            }
            Category category = CategoryOf(entry, tuple);
            if (is_dir) category = DirectoryCategoryOf(entry);
            Choice choice = ChooseType(category, entry, ctx);
            ctx.plan->new_types[choice.type] = choice.attributes;
            ctx.plan->AddLine(home + "/file.te", choice.declaration);
            ctx.plan->AddLine(home + "/file_contexts",
                              FileContextsLine(entry, is_dir, choice.type));
            if (home == "vendor" && ctx.IsPlatformDomain(domain)) {
                // The label is still needed, but the platform's rule cannot name it.
                ctx.Note(domain,
                         "is a private platform domain, which cannot refer to the vendor "
                         "type " +
                                 choice.type + "; give " + entry +
                                 " a type the platform knows, or an attribute");
                continue;
            }
            ctx.plan->synthesized.push_back(Retarget(tuple, choice.type));
            handled++;
        }

        // The original denial stays if some of its objects stayed as they are.
        if (handled > 0 &&
            handled == pseudo.size() + CollapseSiblings(regular, kCollapseSiblings).size() &&
            unusable == 0) {
            ctx.plan->replaced.insert(tuple.key);
        }
    }
}

}  // namespace selogger
