/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

#include "avc.h"
#include "config.h"
#include "journal.h"
#include "tuple.h"

namespace selogger {

struct CollectorStatus {
    uint64_t tuples = 0;
    uint64_t evicted = 0;
    uint64_t journal_bytes = 0;
    uint64_t denials_seen = 0;
    uint64_t parse_failures = 0;
    uint64_t kernel_lost = 0;  // highest audit_lost counter seen this boot
    bool collecting = false;
    int64_t seconds_since_new_tuple = 0;
};

std::string FormatStatus(const CollectorStatus& status);

// Aggregates denials and decides when to write them out.
//
// The collector never reads a clock and never sleeps: callers pass the
// monotonic time in seconds and obey the delay Tick() returns. That keeps the
// daemon free of timers while there is nothing to do, and keeps this class
// testable.
class Collector {
  public:
    Collector(Config config, std::string boot_id);

    // Loads the journal.
    bool Init(int64_t now);

    // Returns true if the caller should wake the thread that runs Tick(),
    // because this denial created work that was not scheduled yet.
    bool OnDenial(const AvcDenial& denial, uint64_t entry_ns, int64_t entry_time_s, int64_t now);
    // Returns whether the caller should wake the main loop.
    bool OnKernelLost(uint64_t lost, int64_t now);
    void OnParseFailure();

    struct TickResult {
        // Seconds until Tick() has to run again; negative if nothing is due.
        int64_t next_in_s = -1;
        // Set when the collector went idle; the caller lowers the audit rate.
        std::optional<bool> set_collecting;
    };
    TickResult Tick(int64_t now);

    void SetCollecting(bool collecting, int64_t now);
    bool collecting() const;

    // Writes everything, counters included.
    bool Flush();
    // Forgets all denials, in memory and on disk.
    bool Clear();

    CollectorStatus Status(int64_t now) const;
    // Time of the newest log entry seen; reading resumes after it.
    uint64_t resume_ns() const;

  private:
    bool FlushLocked(bool include_counts);
    int64_t NextDeadlineLocked(int64_t now) const;

    const Config config_;
    const std::string boot_id_;
    mutable std::mutex mutex_;
    TupleTable table_;
    Journal journal_;
    JournalMeta meta_;
    bool collecting_ = false;
    int64_t last_new_tuple_ = 0;
    // Monotonic time work became pending; 0 if there is none.
    int64_t structure_pending_since_ = 0;
    bool meta_dirty_ = false;
    int64_t counts_pending_since_ = 0;
    uint64_t denials_seen_ = 0;
    uint64_t parse_failures_ = 0;
    uint64_t kernel_lost_ = 0;
};

}  // namespace selogger
