/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <stdlib.h>
#include <unistd.h>

#include "collector.h"

namespace selogger {

namespace {

AvcDenial Denial(const std::string& perm, const std::string& ttype = "vendor_file") {
    auto d = ParseAvc("type=1400 audit(0.0:1): avc:  denied  { " + perm +
                      " } for  comm=\"foo\" scontext=u:r:hal_foo:s0 tcontext=u:object_r:" + ttype +
                      ":s0 tclass=file permissive=0");
    EXPECT_TRUE(d.has_value());
    return *d;
}

class CollectorTest : public testing::Test {
  protected:
    void SetUp() override {
        char dir[] = "/tmp/selogger_collector_XXXXXX";
        ASSERT_NE(mkdtemp(dir), nullptr);
        config_.state_dir = dir;
        config_.flush_delay_s = 5;
        config_.count_flush_interval_s = 100;
        config_.idle_timeout_s = 50;
    }
    void TearDown() override {
        unlink(config_.journal_path().c_str());
        unlink((config_.journal_path() + ".tmp").c_str());
        rmdir(config_.state_dir.c_str());
    }

    uint64_t JournalTuples() {
        TupleTable table(1000, 16);
        JournalMeta meta;
        Journal(config_.journal_path()).Load(&table, &meta);
        return table.size();
    }

    Config config_;
};

}  // namespace

TEST_F(CollectorTest, NewTupleIsWrittenAfterTheDelay) {
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    EXPECT_TRUE(c.OnDenial(Denial("read"), 1000, 1, 10));
    // A second denial while work is pending needs no new wake-up.
    EXPECT_FALSE(c.OnDenial(Denial("write"), 1001, 1, 11));

    auto r = c.Tick(12);
    EXPECT_EQ(JournalTuples(), 0u);
    EXPECT_EQ(r.next_in_s, 3);  // 10 + 5 - 12

    r = c.Tick(15);
    EXPECT_EQ(JournalTuples(), 1u);
    EXPECT_GT(r.next_in_s, 5);  // counters are next, a hundred seconds out
}

TEST_F(CollectorTest, RepeatsOnlyFlushWithTheCounterInterval) {
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    c.OnDenial(Denial("read"), 1, 1, 10);
    c.Tick(20);
    uint64_t size = c.Status(20).journal_bytes;

    c.OnDenial(Denial("read"), 2, 2, 30);
    c.Tick(40);
    EXPECT_EQ(c.Status(40).journal_bytes, size);  // nothing written yet

    c.Tick(30 + 100);
    EXPECT_GT(c.Status(130).journal_bytes, size);
}

TEST_F(CollectorTest, ReloadsWhatWasWritten) {
    {
        Collector c(config_, "boot");
        ASSERT_TRUE(c.Init(1));
        c.OnDenial(Denial("read"), 777, 1, 10);
        c.OnDenial(Denial("read", "other"), 888, 1, 10);
        ASSERT_TRUE(c.Flush());
    }
    Collector again(config_, "boot2");
    ASSERT_TRUE(again.Init(1));
    EXPECT_EQ(again.Status(1).tuples, 2u);
    EXPECT_EQ(again.resume_ns(), 888u);
}

TEST_F(CollectorTest, GoesIdleWithoutNewTuples) {
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    c.SetCollecting(true, 10);
    auto r = c.Tick(20);
    EXPECT_FALSE(r.set_collecting.has_value());
    EXPECT_EQ(r.next_in_s, 40);  // 10 + 50 - 20

    // A new kind of denial postpones it, a repeat does not.
    c.OnDenial(Denial("read"), 1, 1, 40);
    r = c.Tick(45);
    EXPECT_FALSE(r.set_collecting.has_value());
    c.OnDenial(Denial("read"), 2, 1, 80);
    r = c.Tick(90);
    ASSERT_TRUE(r.set_collecting.has_value());
    EXPECT_FALSE(*r.set_collecting);
    EXPECT_FALSE(c.collecting());
}

TEST_F(CollectorTest, IdleTimeoutZeroNeverGoesIdle) {
    config_.idle_timeout_s = 0;
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    c.SetCollecting(true, 10);
    auto r = c.Tick(100000);
    EXPECT_FALSE(r.set_collecting.has_value());
    EXPECT_LT(r.next_in_s, 0);
    EXPECT_TRUE(c.collecting());
}

TEST_F(CollectorTest, JournalIsCompactedWhenItGrows) {
    config_.journal_max_bytes = 64 << 10;
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    int64_t now = 10;
    for (int round = 0; round < 400; round++) {
        c.OnDenial(Denial("read"), round, 1, now);
        c.OnDenial(Denial("write"), round, 1, now);
        c.Tick(now += 10);
        c.OnDenial(Denial("read", "t" + std::to_string(round % 5)), round, 1, now);
        c.Tick(now += 10);
    }
    c.Flush();
    EXPECT_LE(c.Status(now).journal_bytes, 2u * config_.journal_max_bytes);
    EXPECT_EQ(JournalTuples(), c.Status(now).tuples);
}

TEST_F(CollectorTest, ClearForgetsEverything) {
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    c.OnDenial(Denial("read"), 1, 1, 10);
    ASSERT_TRUE(c.Flush());
    ASSERT_TRUE(c.Clear());
    EXPECT_EQ(c.Status(10).tuples, 0u);
    EXPECT_EQ(JournalTuples(), 0u);
    EXPECT_LT(c.Tick(20).next_in_s, 0);
}

TEST_F(CollectorTest, StatusCountsLostAndParseFailures) {
    Collector c(config_, "boot");
    ASSERT_TRUE(c.Init(1));
    c.OnKernelLost(5);
    c.OnKernelLost(3);  // the counter only grows
    c.OnParseFailure();
    auto s = c.Status(1);
    EXPECT_EQ(s.kernel_lost, 5u);
    EXPECT_EQ(s.parse_failures, 1u);
    EXPECT_NE(FormatStatus(s).find("kernel_lost: 5"), std::string::npos);
}

}  // namespace selogger
