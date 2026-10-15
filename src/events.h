/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace selogger {

// logd stores audit messages in the events buffer under this tag.
inline constexpr uint32_t kAuditdEventTag = 1003;

// Returns the audit message of an events-buffer payload (tag, type, length,
// string), or nullopt if the payload is something else or truncated.
std::optional<std::string_view> DecodeAuditEvent(std::string_view payload);

// "audit: audit_lost=12 audit_rate_limit=5 ..." from the kernel log: the
// number of audit messages the kernel dropped so far.
std::optional<uint64_t> ParseAuditLost(std::string_view kernel_message);

// "type=1305 ... op=set audit_rate_limit=5 old=0 ..." from the audit stream:
// the new rate limit someone configured.
std::optional<uint32_t> ParseRateLimitChange(std::string_view audit_message);

}  // namespace selogger
