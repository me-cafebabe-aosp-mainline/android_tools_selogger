/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/control.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <errno.h>
#include <sys/socket.h>

namespace selogger {

namespace {

void SetTimeout(int fd) {
    timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

}  // namespace

bool ControlServer::Run() {
    int listen_fd = android_get_control_socket(kControlSocketName);
    if (listen_fd < 0) {
        LOG(ERROR) << "No control socket \"" << kControlSocketName << "\" from init";
        return false;
    }
    if (listen(listen_fd, 4) < 0) {
        PLOG(ERROR) << "Cannot listen on the control socket";
        return false;
    }

    for (;;) {
        android::base::unique_fd client(
                TEMP_FAILURE_RETRY(accept4(listen_fd, nullptr, nullptr, SOCK_CLOEXEC)));
        if (client < 0) {
            PLOG(ERROR) << "accept failed";
            return false;
        }
        SetTimeout(client);

        char buffer[256];
        ssize_t n = TEMP_FAILURE_RETRY(recv(client, buffer, sizeof(buffer) - 1, 0));
        if (n <= 0) continue;
        std::string command = android::base::Trim(std::string(buffer, n));

        std::string reply = handler_(command);
        android::base::WriteFully(client, reply.data(), reply.size());
    }
}

std::optional<std::string> SendControlCommand(const std::string& command) {
    android::base::unique_fd fd(socket_local_client(
            kControlSocketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM));
    if (fd < 0) return std::nullopt;
    SetTimeout(fd);

    std::string line = command + "\n";
    if (!android::base::WriteFully(fd, line.data(), line.size())) return std::nullopt;

    std::string reply;
    if (!android::base::ReadFdToString(fd, &reply)) return std::nullopt;
    return reply;
}

}  // namespace selogger
