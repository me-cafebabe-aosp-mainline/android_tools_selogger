/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace selogger {

inline constexpr char kDefaultConfigPath[] = "/vendor/etc/selogger.conf";

// Every key can be set in the configuration file; the defaults work as is.
// See README.md for the meaning of each.
struct Config {
    std::string state_dir = "/data/vendor/selogger";
    uint64_t max_tuples = 20000;
    uint64_t max_hints = 16;
    int64_t flush_delay_s = 5;
    int64_t count_flush_interval_s = 3600;
    uint64_t journal_max_bytes = 1 << 20;
    // Seconds without a new tuple before the audit rate goes back to
    // idle_audit_rate; 0 never does.
    int64_t idle_timeout_s = 600;
    // Kernel audit rate limit (messages per second, 0 = unlimited) while
    // collecting and when idle.
    uint32_t collect_audit_rate = 100;
    uint32_t idle_audit_rate = 5;
    bool start_collecting = true;
    bool watch_audit_lost = true;

    std::string journal_path() const { return state_dir + "/denials.journal"; }
};

// Applies "key=value" lines on top of *config. Unknown keys, malformed lines
// and out-of-range values are reported in *errors and otherwise ignored.
void ParseConfig(std::string_view text, Config* config, std::vector<std::string>* errors);

}  // namespace selogger
