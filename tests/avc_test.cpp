/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "avc.h"

namespace selogger {

TEST(AvcTest, ParsesFileDenial) {
    auto d = ParseAvc(
            "type=1400 audit(0.0:45): avc:  denied  { read open } for  comm=\"foo\" "
            "name=\"bar\" dev=\"dm-4\" ino=123 scontext=u:r:hal_foo:s0 "
            "tcontext=u:object_r:vendor_file:s0 tclass=file permissive=0 bug=b/1");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->perms, (std::vector<std::string>{"read", "open"}));
    EXPECT_EQ(d->stype, "hal_foo");
    EXPECT_EQ(d->ttype, "vendor_file");
    EXPECT_EQ(d->tclass, "file");
    EXPECT_FALSE(d->permissive);
    EXPECT_EQ(d->Get("comm"), "foo");
    EXPECT_EQ(d->Get("name"), "bar");
    EXPECT_EQ(d->Get("dev"), "dm-4");
    EXPECT_EQ(d->Get("ino"), "123");
    EXPECT_EQ(d->Get("bug"), "b/1");
    EXPECT_EQ(d->Get("missing"), "");
}

TEST(AvcTest, ParsesPermissiveAndCategories) {
    auto d = ParseAvc(
            "type=1400 audit(0.0:1): avc:  denied  { write } for  comm=\"x\" "
            "scontext=u:r:untrusted_app:s0:c512,c768 tcontext=u:object_r:foo:s0 "
            "tclass=dir permissive=1");
    ASSERT_TRUE(d.has_value());
    EXPECT_TRUE(d->permissive);
    EXPECT_EQ(d->stype, "untrusted_app");
}

TEST(AvcTest, ParsesPropertyDenial) {
    auto d = ParseAvc(
            "type=1400 audit(0.0:2): avc:  denied  { set } for property=vendor.foo.bar "
            "uid=1000 gid=1000 scontext=u:r:hal_foo:s0 "
            "tcontext=u:object_r:vendor_default_prop:s0 tclass=property_service permissive=0");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->Get("property"), "vendor.foo.bar");
    EXPECT_EQ(d->tclass, "property_service");
}

TEST(AvcTest, DecodesHexPathButNotServiceNames) {
    // "/dev/a b" in hex.
    auto d = ParseAvc(
            "type=1400 audit(0.0:3): avc:  denied  { read } for  comm=\"x\" "
            "path=2F6465762F612062 dev=\"tmpfs\" ino=7 scontext=u:r:a:s0 "
            "tcontext=u:object_r:b:s0 tclass=chr_file permissive=0");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->Get("path"), "/dev/a b");

    // A service called "cafe" is not hex.
    d = ParseAvc(
            "type=1400 audit(0.0:4): avc:  denied  { find } for  name=cafe "
            "scontext=u:r:a:s0 tcontext=u:object_r:default_android_service:s0 "
            "tclass=service_manager permissive=0");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->Get("name"), "cafe");
}

TEST(AvcTest, KeepsQuotedValueWithSpaces) {
    auto d = ParseAvc(
            "type=1400 audit(0.0:5): avc:  denied  { read } for  comm=\"Binder Thread\" "
            "scontext=u:r:a:s0 tcontext=u:object_r:b:s0 tclass=file permissive=0");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->Get("comm"), "Binder Thread");
}

TEST(AvcTest, ParsesIoctl) {
    auto d = ParseAvc(
            "type=1400 audit(0.0:6): avc:  denied  { ioctl } for  comm=\"x\" path=\"/dev/foo\" "
            "dev=\"tmpfs\" ino=9 ioctlcmd=0x5401 scontext=u:r:a:s0 tcontext=u:object_r:b:s0 "
            "tclass=chr_file permissive=0");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->Get("ioctlcmd"), "0x5401");
    EXPECT_EQ(d->Get("path"), "/dev/foo");
}

TEST(AvcTest, RejectsNonDenials) {
    EXPECT_FALSE(ParseAvc("").has_value());
    EXPECT_FALSE(ParseAvc("type=1403 audit(0.0:7): policy loaded auid=4294967295").has_value());
    EXPECT_FALSE(ParseAvc("type=1400 audit(0.0:8): avc:  granted  { read } for  "
                          "scontext=u:r:a:s0 tcontext=u:object_r:b:s0 tclass=file")
                         .has_value());
    // Missing class.
    EXPECT_FALSE(ParseAvc("avc:  denied  { read } for scontext=u:r:a:s0 tcontext=u:object_r:b:s0")
                         .has_value());
    // Empty permission set.
    EXPECT_FALSE(ParseAvc("avc:  denied  {  } for scontext=u:r:a:s0 tcontext=u:object_r:b:s0 "
                          "tclass=file")
                         .has_value());
    // Malformed context.
    EXPECT_FALSE(ParseAvc("avc:  denied  { read } for scontext=junk tcontext=u:object_r:b:s0 "
                          "tclass=file")
                         .has_value());
}

TEST(AvcTest, TypeOfContext) {
    EXPECT_EQ(TypeOfContext("u:r:init:s0"), "init");
    EXPECT_EQ(TypeOfContext("u:object_r:foo_exec:s0:c1,c2"), "foo_exec");
    EXPECT_EQ(TypeOfContext("bogus"), "");
}

TEST(AvcTest, DecodeAuditHex) {
    EXPECT_EQ(DecodeAuditHex("41424344"), "ABCD");
    EXPECT_FALSE(DecodeAuditHex("4").has_value());
    EXPECT_FALSE(DecodeAuditHex("zz").has_value());
    EXPECT_FALSE(DecodeAuditHex("0001").has_value());  // control characters
}

}  // namespace selogger
