/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <functional>
#include <optional>
#include <string>

namespace selogger {

// The command line talks to the daemon through two files in the state
// directory. A socket or a property would be simpler, but Treble forbids a
// core domain such as the adb shell from connecting to the socket of a
// vendor domain or from setting vendor properties.
//
//   command  "<token> <command>", created by the command line
//   reply    "<token>\n<text>", created by the daemon, which then removes
//            the command
inline constexpr char kCommandFile[] = "command";
inline constexpr char kReplyFile[] = "reply";

// Serves the commands. The thread sleeps in a read on an inotify watch of
// the state directory, so an idle daemon costs nothing.
class ControlServer {
  public:
    using Handler = std::function<std::string(const std::string& command)>;

    ControlServer(std::string state_dir, Handler handler)
        : state_dir_(std::move(state_dir)), handler_(std::move(handler)) {}

    // Blocks; returns only if the directory cannot be watched.
    void Run();

  private:
    void ServeCommand();

    std::string state_dir_;
    Handler handler_;
};

// Sends a command to the running daemon and returns what it printed. Returns
// nullopt if the daemon does not answer.
std::optional<std::string> SendControlCommand(const std::string& state_dir,
                                              const std::string& command);

}  // namespace selogger
