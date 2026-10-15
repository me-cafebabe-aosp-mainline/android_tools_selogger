/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "tuple.h"

namespace selogger {

namespace {

AvcDenial Denial(const std::string& perms, const std::string& extra = "",
                 const std::string& tclass = "file", const std::string& ttype = "vendor_file") {
    auto d = ParseAvc("type=1400 audit(0.0:1): avc:  denied  { " + perms + " } for  comm=\"foo\" " +
                      extra + " scontext=u:r:hal_foo:s0 tcontext=u:object_r:" + ttype +
                      ":s0 tclass=" + tclass + " permissive=0");
    EXPECT_TRUE(d.has_value());
    return *d;
}

Observation Obs(int64_t t = 100, const std::string& boot = "b1") {
    return {t, boot};
}

}  // namespace

TEST(TupleTableTest, NewTupleIsStructural) {
    TupleTable table(100, 4);
    EXPECT_EQ(table.Add(Denial("read"), Obs()), TupleTable::Change::kStructure);
    ASSERT_EQ(table.size(), 1u);
    const Tuple& t = table.tuples().begin()->second;
    EXPECT_EQ(t.count, 1u);
    EXPECT_EQ(t.first_seen, 100);
    EXPECT_EQ(t.boots, 1u);
    EXPECT_TRUE(t.saw_enforcing);
    EXPECT_FALSE(t.saw_permissive);
}

TEST(TupleTableTest, RepeatOnlyMovesCounters) {
    TupleTable table(100, 4);
    table.Add(Denial("read"), Obs(100));
    EXPECT_EQ(table.Add(Denial("read"), Obs(200)), TupleTable::Change::kCount);
    const Tuple& t = table.tuples().begin()->second;
    EXPECT_EQ(t.count, 2u);
    EXPECT_EQ(t.last_seen, 200);
    EXPECT_EQ(t.boots, 1u);
}

TEST(TupleTableTest, NewPermissionHintOrBootIsDetected) {
    TupleTable table(100, 4);
    table.Add(Denial("read", "name=\"a\""), Obs());
    EXPECT_EQ(table.Add(Denial("write", "name=\"a\""), Obs()), TupleTable::Change::kStructure);
    EXPECT_EQ(table.Add(Denial("write", "name=\"b\""), Obs()), TupleTable::Change::kStructure);
    EXPECT_EQ(table.Add(Denial("write", "name=\"b\""), Obs(300, "b2")), TupleTable::Change::kCount);
    const Tuple& t = table.tuples().begin()->second;
    EXPECT_EQ(t.perms, (std::set<std::string>{"read", "write"}));
    EXPECT_EQ(t.hints.at(kHintName), (std::set<std::string>{"a", "b"}));
    EXPECT_EQ(t.boots, 2u);
}

TEST(TupleTableTest, HintsAreBounded) {
    TupleTable table(100, 2);
    for (int i = 0; i < 10; i++) {
        table.Add(Denial("read", "name=\"n" + std::to_string(i) + "\""), Obs());
    }
    EXPECT_EQ(table.tuples().begin()->second.hints.at(kHintName).size(), 2u);
    EXPECT_EQ(table.tuples().begin()->second.count, 10u);
}

TEST(TupleTableTest, PermissiveAndEnforcingAreTracked) {
    TupleTable table(100, 4);
    auto d = Denial("read");
    table.Add(d, Obs());
    d.permissive = true;
    EXPECT_EQ(table.Add(d, Obs()), TupleTable::Change::kStructure);
    const Tuple& t = table.tuples().begin()->second;
    EXPECT_TRUE(t.saw_enforcing);
    EXPECT_TRUE(t.saw_permissive);
}

TEST(TupleTableTest, IoctlCommandsAreCollected) {
    TupleTable table(100, 4);
    table.Add(Denial("ioctl", "path=\"/dev/x\" ioctlcmd=0x5401", "chr_file"), Obs());
    table.Add(Denial("ioctl", "path=\"/dev/x\" ioctlcmd=0x5402", "chr_file"), Obs());
    EXPECT_EQ(table.tuples().begin()->second.ioctls, (std::set<std::string>{"0x5401", "0x5402"}));
}

TEST(TupleTableTest, ServiceAndPropertyHints) {
    AvcDenial svc =
            Denial("find", "name=foo.IBar/default", "service_manager", "default_android_service");
    auto hints = ExtractHints(svc);
    EXPECT_NE(std::find(hints.begin(), hints.end(),
                        std::make_pair(std::string(kHintService), std::string("foo.IBar/default"))),
              hints.end());

    AvcDenial prop = Denial("set", "property=vendor.foo", "property_service", "default_prop");
    hints = ExtractHints(prop);
    EXPECT_NE(std::find(hints.begin(), hints.end(),
                        std::make_pair(std::string(kHintProperty), std::string("vendor.foo"))),
              hints.end());
}

TEST(TupleTableTest, EvictsOldestWhenFull) {
    TupleTable table(10, 4);
    for (int i = 0; i < 11; i++) {
        table.Add(Denial("read", "", "file", "t" + std::to_string(i)), Obs(100 + i));
    }
    EXPECT_LE(table.size(), 10u);
    EXPECT_EQ(table.evicted(), 1u);
    // The oldest tuple is the one that went.
    EXPECT_FALSE(table.tuples().contains(TupleKey{"hal_foo", "t0", "file"}));
    EXPECT_TRUE(table.tuples().contains(TupleKey{"hal_foo", "t10", "file"}));
}

TEST(TupleTableTest, TakeDirty) {
    TupleTable table(100, 4);
    table.Add(Denial("read"), Obs());
    EXPECT_TRUE(table.HasDirty(false));
    EXPECT_EQ(table.TakeDirty(false).size(), 1u);
    EXPECT_FALSE(table.HasDirty(true));

    table.Add(Denial("read"), Obs());  // counter only
    EXPECT_FALSE(table.HasDirty(false));
    EXPECT_TRUE(table.HasDirty(true));
    EXPECT_TRUE(table.TakeDirty(false).empty());
    EXPECT_EQ(table.TakeDirty(true).size(), 1u);
    EXPECT_FALSE(table.HasDirty(true));
}

}  // namespace selogger
