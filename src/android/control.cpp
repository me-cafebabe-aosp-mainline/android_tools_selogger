/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/control.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <chrono>
#include <thread>

namespace selogger {

namespace {

constexpr std::chrono::seconds kReplyTimeout(5);
constexpr std::chrono::milliseconds kReplyPoll(50);
// The command is readable by the daemon, which is not in the shell's group.
constexpr mode_t kCommandMode = 0664;
// The state directory is setgid, so the group is the shell's.
constexpr mode_t kReplyMode = 0640;

bool WriteAtomically(const std::string& path, const std::string& content, mode_t mode) {
    std::string tmp = path + ".tmp";
    if (!android::base::WriteStringToFile(content, tmp, mode, static_cast<uid_t>(-1),
                                          static_cast<gid_t>(-1))) {
        return false;
    }
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

}  // namespace

void ControlServer::ServeCommand() {
    std::string command_path = state_dir_ + "/" + kCommandFile;
    std::string request;
    if (!android::base::ReadFileToString(command_path, &request)) return;
    unlink(command_path.c_str());

    size_t space = request.find(' ');
    if (space == std::string::npos) return;
    std::string reply = handler_(request.substr(space + 1));
    if (!WriteAtomically(state_dir_ + "/" + kReplyFile, request.substr(0, space) + "\n" + reply,
                         kReplyMode)) {
        PLOG(ERROR) << "Cannot write the reply";
    }
}

void ControlServer::Run() {
    android::base::unique_fd fd(inotify_init1(IN_CLOEXEC));
    if (fd < 0 || inotify_add_watch(fd, state_dir_.c_str(), IN_MOVED_TO | IN_CLOSE_WRITE) < 0) {
        PLOG(ERROR) << "Cannot watch " << state_dir_ << "; the command line will not work";
        return;
    }

    for (;;) {
        // A command may have arrived before the watch, or together with
        // another event, so look before every sleep.
        ServeCommand();
        char events[4096];
        if (TEMP_FAILURE_RETRY(read(fd, events, sizeof(events))) < 0) {
            PLOG(ERROR) << "Cannot read the inotify events";
            return;
        }
    }
}

std::optional<std::string> SendControlCommand(const std::string& state_dir,
                                              const std::string& command) {
    // Unique enough: only one command line runs at a time.
    std::string token = std::to_string(getpid()) + "-" + std::to_string(time(nullptr));
    std::string reply_path = state_dir + "/" + kReplyFile;
    unlink(reply_path.c_str());
    if (!WriteAtomically(state_dir + "/" + kCommandFile, token + " " + command, kCommandMode)) {
        PLOG(ERROR) << "Cannot write the command to " << state_dir;
        return std::nullopt;
    }

    auto deadline = std::chrono::steady_clock::now() + kReplyTimeout;
    while (std::chrono::steady_clock::now() < deadline) {
        std::string reply;
        if (android::base::ReadFileToString(reply_path, &reply) &&
            reply.starts_with(token + "\n")) {
            return reply.substr(token.size() + 1);
        }
        std::this_thread::sleep_for(kReplyPoll);
    }
    return std::nullopt;
}

}  // namespace selogger
