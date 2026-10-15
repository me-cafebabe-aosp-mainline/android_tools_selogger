/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include <cstdio>
#include <string>

#include "android/control.h"
#include "android/daemon.h"
#include "android/dump.h"
#include "config.h"

namespace {

constexpr char kUsage[] =
        "Usage: selogger <command>\n"
        "\n"
        "Commands:\n"
        "  daemon [--config FILE]  run the collector (started by init)\n"
        "  status                  show what the collector has seen\n"
        "  dump [--out-dir DIR]    write sepolicy for the collected denials (see dump )\n"
        "  flush                   write pending counters to disk\n"
        "  clear                   forget all collected denials\n"
        "  collect on|off          raise or restore the kernel audit rate limit\n";

std::string ReadBootId() {
    std::string id;
    android::base::ReadFileToString("/proc/sys/kernel/random/boot_id", &id);
    id = android::base::StringReplace(android::base::Trim(id), "-", "", true);
    return id.substr(0, 8);
}

int RunControlCommand(const std::string& command) {
    auto reply = selogger::SendControlCommand(command);
    if (!reply) {
        fprintf(stderr, "selogger: the daemon is not running (or this user may not talk to it)\n");
        return 1;
    }
    fputs(reply->c_str(), stdout);
    return reply->starts_with("error") ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        fputs(kUsage, stderr);
        return 1;
    }
    std::string command = argv[1];

    if (command == "daemon") {
        android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));
        android::base::SetDefaultTag("selogger");
        std::string config_path = selogger::kDefaultConfigPath;
        if (argc == 4 && std::string(argv[2]) == "--config") config_path = argv[3];
        selogger::Daemon daemon(selogger::LoadConfig(config_path), ReadBootId());
        return daemon.Run();
    }

    android::base::InitLogging(argv, android::base::StderrLogger);
    if (command == "dump") {
        return selogger::RunDump(std::vector<std::string>(argv + 2, argv + argc));
    }
    if (command == "status" || command == "flush" || command == "clear") {
        return RunControlCommand(command);
    }
    if (command == "collect" && argc == 3 &&
        (std::string(argv[2]) == "on" || std::string(argv[2]) == "off")) {
        return RunControlCommand(command + " " + argv[2]);
    }

    fputs(kUsage, stderr);
    return 1;
}
