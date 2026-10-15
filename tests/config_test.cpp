/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "config.h"

namespace selogger {

TEST(ConfigTest, DefaultsWithoutFile) {
    Config c;
    std::vector<std::string> errors;
    ParseConfig("", &c, &errors);
    EXPECT_TRUE(errors.empty());
    EXPECT_EQ(c.state_dir, "/data/vendor/selogger");
    EXPECT_EQ(c.journal_path(), "/data/vendor/selogger/denials.journal");
    EXPECT_EQ(c.collect_audit_rate, 100u);
    EXPECT_EQ(c.idle_audit_rate, 5u);
}

TEST(ConfigTest, AppliesValuesCommentsAndWhitespace) {
    Config c;
    std::vector<std::string> errors;
    ParseConfig(
            "# comment\n\n  max_tuples = 500 \nidle_timeout_s=0\nstart_collecting=false\n"
            "state_dir=/data/vendor/x\ncollect_audit_rate=0\n",
            &c, &errors);
    EXPECT_TRUE(errors.empty());
    EXPECT_EQ(c.max_tuples, 500u);
    EXPECT_EQ(c.idle_timeout_s, 0);
    EXPECT_FALSE(c.start_collecting);
    EXPECT_EQ(c.state_dir, "/data/vendor/x");
    EXPECT_EQ(c.collect_audit_rate, 0u);
}

TEST(ConfigTest, RejectsBadInputAndKeepsDefaults) {
    Config c;
    std::vector<std::string> errors;
    ParseConfig(
            "max_tuples=5\nmax_tuples=abc\nflush_delay_s=-1\nstate_dir=relative\n"
            "bogus=1\nnot a pair\nstart_collecting=maybe\n",
            &c, &errors);
    EXPECT_EQ(errors.size(), 7u);
    EXPECT_EQ(c.max_tuples, 20000u);
    EXPECT_EQ(c.flush_delay_s, 5);
    EXPECT_EQ(c.state_dir, "/data/vendor/selogger");
    EXPECT_TRUE(c.start_collecting);
}

}  // namespace selogger
