/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>

#include "collector.h"
#include "config.h"

namespace selogger {

// The service: reads denials from logd into a Collector and keeps the kernel
// audit rate limit where the collector wants it.
//
// Threads: the reader (blocks on logd), the control socket server, a signal
// waiter, and the calling thread, which runs the collector's timers. All of
// them block until there is something to do.
class Daemon {
  public:
    Daemon(Config config, std::string boot_id);

    int Run();

  private:
    void ReaderLoop();
    void ControlLoop();
    void HandleEntry(const struct LogEntry& entry);
    void HandleRateChange(uint32_t rate);
    std::string HandleCommand(const std::string& command);

    // Applies the audit rate for the collecting or idle state.
    void ApplyState(bool collecting);
    void Kick();
    void Stop();

    const Config config_;
    Collector collector_;

    std::mutex wake_mutex_;
    std::condition_variable wake_cv_;
    bool kick_ = false;
    std::atomic<bool> stop_ = false;

    std::atomic<int64_t> last_rate_fix_ = 0;
};

// Monotonic seconds, not counting suspend: timers do not wake the device.
int64_t MonotonicSeconds();

}  // namespace selogger
