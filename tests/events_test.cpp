/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <cstring>

#include "events.h"

namespace selogger {

namespace {

std::string Event(uint32_t tag, uint8_t type, const std::string& text,
                  uint32_t length_override = 0) {
    std::string out(9, '\0');
    std::memcpy(out.data(), &tag, 4);
    out[4] = static_cast<char>(type);
    uint32_t length = length_override ? length_override : text.size();
    std::memcpy(out.data() + 5, &length, 4);
    return out + text;
}

}  // namespace

TEST(EventsTest, DecodesAuditString) {
    EXPECT_EQ(DecodeAuditEvent(Event(1003, 2, "type=1400 avc")), "type=1400 avc");
}

TEST(EventsTest, DecodesWhatLogdSends) {
    // The start of an event as seen on a device: tag 1003, string, length 3.
    const std::string wire("\xeb\x03\x00\x00\x02\x03\x00\x00\x00""abc", 12);
    EXPECT_EQ(DecodeAuditEvent(wire), "abc");
}

TEST(EventsTest, RejectsOtherTagsTypesAndTruncation) {
    EXPECT_FALSE(DecodeAuditEvent(Event(42, 2, "x")).has_value());
    EXPECT_FALSE(DecodeAuditEvent(Event(1003, 0, "x")).has_value());
    EXPECT_FALSE(DecodeAuditEvent(Event(1003, 2, "short", 100)).has_value());
    EXPECT_FALSE(DecodeAuditEvent("").has_value());
    EXPECT_FALSE(DecodeAuditEvent("12345678").has_value());
}

TEST(EventsTest, ParsesAuditLost) {
    EXPECT_EQ(ParseAuditLost("audit: audit_lost=1234 audit_rate_limit=5 audit_backlog_limit=64"),
              1234u);
    EXPECT_FALSE(ParseAuditLost("audit: something else").has_value());
    EXPECT_FALSE(ParseAuditLost("audit_lost=x").has_value());
}

TEST(EventsTest, ParsesRateLimitChange) {
    EXPECT_EQ(ParseRateLimitChange("type=1305 audit(0.0:9): op=set audit_rate_limit=5 old=0 "
                                   "auid=4294967295 res=1"),
              5u);
    EXPECT_EQ(ParseRateLimitChange("type=1305 audit(0.0:9): op=set audit_rate_limit=0 old=5"), 0u);
    // Other configuration changes and other message types are not it.
    EXPECT_FALSE(ParseRateLimitChange("type=1305 audit(0.0:9): op=set audit_backlog_limit=64 old=1")
                         .has_value());
    EXPECT_FALSE(ParseRateLimitChange("type=1400 op=set audit_rate_limit=5").has_value());
}

}  // namespace selogger
