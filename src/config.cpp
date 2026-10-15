/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "config.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

#include <type_traits>

namespace selogger {

namespace {

template <typename T>
bool ParseRanged(const std::string& value, T min, T max, T* out) {
    T parsed;
    bool ok;
    if constexpr (std::is_signed_v<T>) {
        ok = android::base::ParseInt(value, &parsed);
    } else {
        ok = android::base::ParseUint(value, &parsed);
    }
    if (!ok || parsed < min || parsed > max) return false;
    *out = parsed;
    return true;
}

bool ParseBoolValue(const std::string& value, bool* out) {
    if (value == "true" || value == "1") {
        *out = true;
    } else if (value == "false" || value == "0") {
        *out = false;
    } else {
        return false;
    }
    return true;
}

}  // namespace

void ParseConfig(std::string_view text, Config* config, std::vector<std::string>* errors) {
    for (const std::string& raw : android::base::Split(std::string(text), "\n")) {
        std::string line = android::base::Trim(raw);
        if (line.empty() || line[0] == '#') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            errors->push_back("not a key=value line: " + line);
            continue;
        }
        std::string key = android::base::Trim(line.substr(0, eq));
        std::string value = android::base::Trim(line.substr(eq + 1));

        bool ok = true;
        if (key == "state_dir") {
            ok = value.starts_with("/");
            if (ok) config->state_dir = value;
        } else if (key == "max_tuples") {
            ok = ParseRanged<uint64_t>(value, 100, 1000000, &config->max_tuples);
        } else if (key == "max_hints") {
            ok = ParseRanged<uint64_t>(value, 1, 256, &config->max_hints);
        } else if (key == "flush_delay_s") {
            ok = ParseRanged<int64_t>(value, 0, 3600, &config->flush_delay_s);
        } else if (key == "count_flush_interval_s") {
            ok = ParseRanged<int64_t>(value, 10, 86400, &config->count_flush_interval_s);
        } else if (key == "journal_max_bytes") {
            ok = ParseRanged<uint64_t>(value, 64 << 10, 64 << 20, &config->journal_max_bytes);
        } else if (key == "idle_timeout_s") {
            ok = ParseRanged<int64_t>(value, 0, 7 * 86400, &config->idle_timeout_s);
        } else if (key == "collect_audit_rate") {
            ok = ParseRanged<uint32_t>(value, 0, 100000, &config->collect_audit_rate);
        } else if (key == "idle_audit_rate") {
            ok = ParseRanged<uint32_t>(value, 0, 100000, &config->idle_audit_rate);
        } else if (key == "start_collecting") {
            ok = ParseBoolValue(value, &config->start_collecting);
        } else if (key == "watch_audit_lost") {
            ok = ParseBoolValue(value, &config->watch_audit_lost);
        } else {
            errors->push_back("unknown key: " + key);
            continue;
        }
        if (!ok) errors->push_back("bad value for " + key + ": " + value);
    }
}

Config LoadConfig(const std::string& path) {
    Config config;
    std::string text;
    if (!android::base::ReadFileToString(path, &text)) {
        LOG(INFO) << "No configuration at " << path << ", using defaults";
        return config;
    }
    std::vector<std::string> errors;
    ParseConfig(text, &config, &errors);
    for (const std::string& error : errors) LOG(WARNING) << path << ": " << error;
    return config;
}

}  // namespace selogger
