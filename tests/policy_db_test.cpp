/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "analyze/policy_db.h"

namespace selogger {

namespace {

constexpr char kPlatform[] = R"cil(
; comment (with parens)
(type init)
(type vendor_foo_prop_plat)
(type logd_prop)
(type sysfs)
(typeattribute property_type)
(typeattribute domain)
(typeattributeset domain (init))
(typeattributeset property_type (logd_prop vendor_foo_prop_plat))
(typeattributeset not_prop (not (property_type)))
(typeattributeset both (and (property_type) (logd_prop)))
(typeattributeset everything (all))
(typeattributeset nested (property_type sysfs))
(allow init init (file (read "a string with ( paren")))
(genfscon sysfs "/devices/platform" (u object_r sysfs_platform ((s0) (s0))))
(genfscon sysfs "/devices/platform/soc/x" (u object_r sysfs_x ((s0) (s0))))
(genfscon proc "/sys/kernel/foo" (u object_r proc_foo ((s0) (s0))))
)cil";

constexpr char kVendor[] = R"cil(
(type hal_foo)
(type vendor_data)
(typeattributeset domain (init_202604 hal_foo))
(typeattributeset file_type (vendor_data sysfs_202604))
(typeattributeset property_type (logd_prop_202604 vendor_prop))
(type vendor_prop)
)cil";

}  // namespace

TEST(PolicyDbTest, AttributesTypesAndOrigin) {
    PolicyDb db("202604");
    db.AddCil(kPlatform, PolicyOrigin::kPlatform);
    db.AddCil(kVendor, PolicyOrigin::kVendor);

    EXPECT_TRUE(db.HasType("init"));
    EXPECT_EQ(db.OriginOf("init"), PolicyOrigin::kPlatform);
    EXPECT_EQ(db.OriginOf("hal_foo"), PolicyOrigin::kVendor);
    EXPECT_FALSE(db.OriginOf("nope").has_value());

    EXPECT_TRUE(db.HasAttribute("logd_prop", "property_type"));
    EXPECT_TRUE(db.HasAttribute("vendor_prop", "property_type"));
    EXPECT_TRUE(db.HasAttribute("hal_foo", "domain"));
    EXPECT_TRUE(db.HasAttribute("init", "domain"));
    EXPECT_FALSE(db.HasAttribute("hal_foo", "property_type"));
    EXPECT_FALSE(db.HasAttribute("init", "unknown_attribute"));
}

TEST(PolicyDbTest, PublicTypesAreTheVersionedOnesInTheVendorCil) {
    PolicyDb db("202604");
    db.AddCil(kPlatform, PolicyOrigin::kPlatform);
    db.AddCil(kVendor, PolicyOrigin::kVendor);
    EXPECT_TRUE(db.IsPublic("init"));
    EXPECT_TRUE(db.IsPublic("sysfs"));
    EXPECT_TRUE(db.IsPublic("logd_prop"));
    EXPECT_FALSE(db.IsPublic("vendor_foo_prop_plat"));
    EXPECT_FALSE(db.IsPublic("hal_foo"));
}

TEST(PolicyDbTest, Expressions) {
    PolicyDb db("202604");
    db.AddCil(kPlatform, PolicyOrigin::kPlatform);
    EXPECT_TRUE(db.HasAttribute("init", "not_prop"));
    EXPECT_FALSE(db.HasAttribute("logd_prop", "not_prop"));
    EXPECT_EQ(db.MembersOf("both"), (std::set<std::string>{"logd_prop"}));
    EXPECT_TRUE(db.HasAttribute("sysfs", "everything"));
    // An attribute used inside another set is expanded.
    EXPECT_TRUE(db.HasAttribute("vendor_foo_prop_plat", "nested"));
    EXPECT_TRUE(db.HasAttribute("sysfs", "nested"));
}

TEST(PolicyDbTest, GenfsLongestPrefixWins) {
    PolicyDb db("202604");
    db.AddCil(kPlatform, PolicyOrigin::kPlatform);
    EXPECT_EQ(db.LookupGenfs("sysfs", "/devices/platform/soc/x/y")->type, "sysfs_x");
    EXPECT_EQ(db.LookupGenfs("sysfs", "/devices/platform/soc/other")->type, "sysfs_platform");
    EXPECT_EQ(db.LookupGenfs("sysfs", "/devices/platform")->type, "sysfs_platform");
    EXPECT_FALSE(db.LookupGenfs("sysfs", "/devices/platformx").has_value());
    EXPECT_FALSE(db.LookupGenfs("sysfs", "/class/foo").has_value());
    EXPECT_FALSE(db.LookupGenfs("debugfs", "/devices/platform").has_value());
}

TEST(PolicyDbTest, SurvivesGarbage) {
    PolicyDb db("202604");
    db.AddCil("(((( unbalanced \"string", PolicyOrigin::kPlatform);
    db.AddCil("", PolicyOrigin::kVendor);
    db.AddCil("(typeattributeset a (b)) (typeattributeset b (a))", PolicyOrigin::kPlatform);
    EXPECT_FALSE(db.HasAttribute("x", "a"));  // a cycle ends
}

}  // namespace selogger
