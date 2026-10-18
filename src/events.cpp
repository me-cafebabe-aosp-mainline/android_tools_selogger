/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "events.h"

#include <android-base/parseint.h>

#include <cstring>
#include <string>

namespace selogger {

namespace {

// EVENT_TYPE_STRING in log/log_event_list.h.
constexpr uint8_t kEventTypeString = 2;
constexpr size_t kEventHeaderSize = 4 + 1 + 4;

uint32_t ReadLe32(const char* p) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;  // devices are little-endian, as logd's wire format
}

// Parses the unsigned number after "key=" in text.
template <typename T>
std::optional<T> NumberAfter(std::string_view text, std::string_view key) {
    size_t pos = text.find(key);
    if (pos == std::string_view::npos) return std::nullopt;
    pos += key.size();
    size_t end = pos;
    while (end < text.size() && text[end] >= '0' && text[end] <= '9') end++;
    T value;
    if (end == pos || !android::base::ParseUint(std::string(text.substr(pos, end - pos)), &value)) {
        return std::nullopt;
    }
    return value;
}

}  // namespace

std::optional<std::string_view> DecodeAuditEvent(std::string_view payload) {
    if (payload.size() < kEventHeaderSize) return std::nullopt;
    if (ReadLe32(payload.data()) != kAuditdEventTag) return std::nullopt;
    if (static_cast<uint8_t>(payload[4]) != kEventTypeString) return std::nullopt;
    uint32_t length = ReadLe32(payload.data() + 5);
    if (length > payload.size() - kEventHeaderSize) return std::nullopt;
    return payload.substr(kEventHeaderSize, length);
}

std::optional<uint64_t> ParseAuditLost(std::string_view kernel_message) {
    return NumberAfter<uint64_t>(kernel_message, "audit_lost=");
}

std::optional<uint32_t> ParseRateLimitChange(std::string_view audit_message) {
    if (audit_message.find("type=1305") == std::string_view::npos) return std::nullopt;
    return NumberAfter<uint32_t>(audit_message, "op=set audit_rate_limit=");
}

}  // namespace selogger
