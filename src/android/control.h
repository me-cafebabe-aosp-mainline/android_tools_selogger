/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <functional>
#include <optional>
#include <string>

namespace selogger {

inline constexpr char kControlSocketName[] = "selogger";

// Serves one-line commands on the socket init created for the service. Each
// connection sends a command, gets the handler's reply and is closed.
class ControlServer {
  public:
    using Handler = std::function<std::string(const std::string& command)>;

    explicit ControlServer(Handler handler) : handler_(std::move(handler)) {}

    // Blocks. Returns false if the socket is not available.
    bool Run();

  private:
    Handler handler_;
};

// Sends a command to the running daemon. Returns nullopt if it is not
// reachable.
std::optional<std::string> SendControlCommand(const std::string& command);

}  // namespace selogger
