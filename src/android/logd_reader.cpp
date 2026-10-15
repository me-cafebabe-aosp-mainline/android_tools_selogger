/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/logd_reader.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <errno.h>
#include <sys/socket.h>

#include <cstring>

namespace selogger {

namespace {

// struct logger_entry from log/log_read.h.
struct LoggerEntry {
    uint16_t len;
    uint16_t hdr_size;
    int32_t pid;
    uint32_t tid;
    uint32_t sec;
    uint32_t nsec;
    uint32_t lid;
    uint32_t uid;
};
static_assert(sizeof(LoggerEntry) == 28);

constexpr size_t kMaxEntrySize = 5 * 1024 + 256;

}  // namespace

bool LogdReader::Open(uint64_t resume_ns) {
    fd_.reset(socket_local_client("logdr", ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
    if (fd_ < 0) {
        PLOG(WARNING) << "Cannot connect to logdr";
        return false;
    }

    std::string command = "stream lids=";
    for (size_t i = 0; i < log_ids_.size(); i++) {
        command += (i ? "," : "") + std::to_string(log_ids_[i]);
    }
    if (resume_ns != 0) {
        // Entries with exactly this time were already handled.
        uint64_t start = resume_ns + 1;
        command += android::base::StringPrintf(
                " start=%llu.%09llu", static_cast<unsigned long long>(start / 1000000000ull),
                static_cast<unsigned long long>(start % 1000000000ull));
    }
    // logd expects the terminating NUL as part of the command.
    if (TEMP_FAILURE_RETRY(write(fd_, command.c_str(), command.size() + 1)) < 0) {
        PLOG(WARNING) << "Cannot send \"" << command << "\" to logdr";
        fd_.reset();
        return false;
    }
    LOG(INFO) << "Reading logd: " << command;
    return true;
}

bool LogdReader::Read(LogEntry* entry) {
    char buffer[kMaxEntrySize];
    // SOCK_SEQPACKET: one entry per receive.
    ssize_t n = TEMP_FAILURE_RETRY(recv(fd_, buffer, sizeof(buffer), 0));
    if (n < 0) {
        PLOG(WARNING) << "Cannot read from logdr";
        return false;
    }
    if (n == 0) return false;  // logd closed the connection

    LoggerEntry header;
    if (static_cast<size_t>(n) < sizeof(header)) return true;  // skip the odd packet
    std::memcpy(&header, buffer, sizeof(header));
    if (header.hdr_size < sizeof(header) || header.hdr_size > n) return true;

    size_t payload_size = std::min<size_t>(header.len, n - header.hdr_size);
    entry->log_id = header.lid;
    entry->sec = header.sec;
    entry->nsec = header.nsec;
    entry->payload.assign(buffer + header.hdr_size, payload_size);
    return true;
}

}  // namespace selogger
