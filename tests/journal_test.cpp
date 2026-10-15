/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-base/file.h>
#include <gtest/gtest.h>
#include <stdlib.h>

#include "journal.h"

namespace selogger {

namespace {

Tuple MakeTuple() {
    Tuple t;
    t.key = {"hal_foo", "vendor_file", "file"};
    t.perms = {"open", "read"};
    t.ioctls = {"0x5401"};
    t.hints[kHintPath] = {"/vendor/etc/a b\tc%d"};
    t.hints[kHintComm] = {"foo"};
    t.count = 42;
    t.first_seen = 10;
    t.last_seen = 20;
    t.saw_enforcing = true;
    t.boots = 3;
    t.last_boot = "abcd1234";
    return t;
}

class JournalTest : public testing::Test {
  protected:
    void SetUp() override {
        char dir[] = "/tmp/selogger_test_XXXXXX";
        ASSERT_NE(mkdtemp(dir), nullptr);
        dir_ = dir;
        path_ = dir_ + "/journal";
    }
    void TearDown() override {
        unlink(path_.c_str());
        unlink((path_ + ".tmp").c_str());
        rmdir(dir_.c_str());
    }

    std::string dir_;
    std::string path_;
};

}  // namespace

TEST(JournalFormatTest, RoundTrip) {
    Tuple t = MakeTuple();
    std::string line = SerializeTuple(t);
    ASSERT_EQ(line.back(), '\n');
    EXPECT_EQ(line.find('\n'), line.size() - 1);  // one physical line
    auto parsed = ParseTuple(line.substr(0, line.size() - 1));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->key, t.key);
    EXPECT_EQ(parsed->perms, t.perms);
    EXPECT_EQ(parsed->ioctls, t.ioctls);
    EXPECT_EQ(parsed->hints, t.hints);
    EXPECT_EQ(parsed->count, 42u);
    EXPECT_EQ(parsed->first_seen, 10);
    EXPECT_EQ(parsed->last_seen, 20);
    EXPECT_TRUE(parsed->saw_enforcing);
    EXPECT_FALSE(parsed->saw_permissive);
    EXPECT_EQ(parsed->boots, 3u);
    EXPECT_EQ(parsed->last_boot, "abcd1234");
}

TEST(JournalFormatTest, RejectsDamagedLines) {
    std::string line = SerializeTuple(MakeTuple());
    line.pop_back();
    EXPECT_FALSE(ParseTuple(line.substr(0, line.size() / 2)).has_value());  // cut short
    EXPECT_FALSE(ParseTuple("").has_value());
    EXPECT_FALSE(ParseTuple("garbage").has_value());
    EXPECT_FALSE(ParseTuple("T\tst=a\ttt=b\te=1").has_value());  // no class or permissions
}

TEST_F(JournalTest, MissingFileIsEmpty) {
    TupleTable table(100, 4);
    JournalMeta meta;
    Journal journal(path_);
    EXPECT_TRUE(journal.Load(&table, &meta));
    EXPECT_EQ(table.size(), 0u);
}

TEST_F(JournalTest, AppendedRecordsAreReplacedByLaterOnes) {
    Journal journal(path_);
    Tuple t = MakeTuple();
    ASSERT_TRUE(journal.Append({t}, {5}));
    t.count = 50;
    t.perms.insert("write");
    ASSERT_TRUE(journal.Append({t}, {9}));

    TupleTable table(100, 4);
    JournalMeta meta;
    Journal reader(path_);
    ASSERT_TRUE(reader.Load(&table, &meta));
    ASSERT_EQ(table.size(), 1u);
    const Tuple& loaded = table.tuples().begin()->second;
    EXPECT_EQ(loaded.count, 50u);
    EXPECT_EQ(loaded.perms.size(), 3u);
    EXPECT_EQ(meta.last_entry_ns, 9u);
    EXPECT_FALSE(loaded.dirty_structure);
}

TEST_F(JournalTest, DamagedTailIsIgnored) {
    Journal journal(path_);
    ASSERT_TRUE(journal.Append({MakeTuple()}, {1}));
    std::string content;
    ASSERT_TRUE(android::base::ReadFileToString(path_, &content));
    ASSERT_TRUE(android::base::WriteStringToFile(content + "T\tst=a\ttt=b\ttc=c\tp=r", path_));

    TupleTable table(100, 4);
    JournalMeta meta;
    ASSERT_TRUE(Journal(path_).Load(&table, &meta));
    EXPECT_EQ(table.size(), 1u);
}

TEST_F(JournalTest, RewriteKeepsOneLinePerTuple) {
    Journal journal(path_);
    Tuple t = MakeTuple();
    for (int i = 0; i < 5; i++) {
        t.count = i;
        ASSERT_TRUE(journal.Append({t}, {1}));
    }
    uint64_t before = journal.size_bytes();

    TupleTable table(100, 4);
    JournalMeta meta;
    ASSERT_TRUE(Journal(path_).Load(&table, &meta));
    meta.last_entry_ns = 7;
    ASSERT_TRUE(journal.Rewrite(table, meta));
    EXPECT_LT(journal.size_bytes(), before);
    EXPECT_NE(access((path_ + ".tmp").c_str(), F_OK), 0);

    TupleTable again(100, 4);
    JournalMeta meta2;
    ASSERT_TRUE(Journal(path_).Load(&again, &meta2));
    EXPECT_EQ(again.size(), 1u);
    EXPECT_EQ(meta2.last_entry_ns, 7u);
}

TEST_F(JournalTest, Remove) {
    Journal journal(path_);
    ASSERT_TRUE(journal.Append({MakeTuple()}, {1}));
    EXPECT_TRUE(journal.Remove());
    EXPECT_TRUE(journal.Remove());  // already gone
    TupleTable table(100, 4);
    JournalMeta meta;
    ASSERT_TRUE(journal.Load(&table, &meta));
    EXPECT_EQ(table.size(), 0u);
}

}  // namespace selogger
