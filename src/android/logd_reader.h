/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <android-base/unique_fd.h>

#include <cstdint>
#include <string>
#include <vector>

namespace selogger {

// Buffer ids, as in log/log_id.h.
inline constexpr uint32_t kLogIdEvents = 2;
inline constexpr uint32_t kLogIdKernel = 7;

struct LogEntry {
    uint32_t log_id = 0;
    uint32_t sec = 0;
    uint32_t nsec = 0;
    std::string payload;

    uint64_t ns() const { return static_cast<uint64_t>(sec) * 1000000000ull + nsec; }
};

// Streams log entries from logd's reader socket.
//
// liblog's reader API is not available to vendor modules, but the socket
// protocol under it is stable: send "stream lids=<ids> start=<s>.<ns>" and
// get one logger_entry per packet.
class LogdReader {
  public:
    explicit LogdReader(std::vector<uint32_t> log_ids) : log_ids_(std::move(log_ids)) {}

    // Connects and asks for entries newer than resume_ns, or for everything
    // logd still has if it is 0.
    bool Open(uint64_t resume_ns);

    // Blocks until an entry arrives. Returns false when the connection is gone.
    bool Read(LogEntry* entry);

    void Close() { fd_.reset(); }

  private:
    std::vector<uint32_t> log_ids_;
    android::base::unique_fd fd_;
};

}  // namespace selogger
