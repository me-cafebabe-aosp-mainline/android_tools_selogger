/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "analyze/rulegen.h"

namespace selogger {

namespace {

class NoTypes : public TypeInfo {
  public:
    bool HasAttribute(const std::string&, const std::string&) const override { return false; }
};

Tuple T(const std::string& stype, const std::string& ttype, const std::string& tclass,
        std::set<std::string> perms) {
    Tuple t;
    t.key = {stype, ttype, tclass};
    t.perms = std::move(perms);
    return t;
}

const DomainRules& Find(const RuleSet& set, const std::string& domain) {
    for (const DomainRules& d : set.domains) {
        if (d.domain == domain) return d;
    }
    ADD_FAILURE() << "no rules for " << domain;
    static DomainRules none;
    return none;
}

bool NoteMentions(const RuleSet& set, const std::string& text) {
    for (const ReviewNote& n : set.notes) {
        if (n.text.find(text) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

TEST(RuleGenTest, FormatsAllowRules) {
    EXPECT_EQ(FormatAllow("a", "b", "file", {"read"}), "allow a b:file read;");
    EXPECT_EQ(FormatAllow("a", "b", "file", {"write", "open"}), "allow a b:file { open write };");
}

TEST(RuleGenTest, GroupsBySourceDomainAndSorts) {
    NoTypes types;
    auto set = GenerateRules({T("b_dom", "x", "file", {"read"}), T("a_dom", "y", "file", {"read"}),
                              T("a_dom", "x", "dir", {"search"})},
                             types, nullptr);
    ASSERT_EQ(set.domains.size(), 2u);
    EXPECT_EQ(set.domains[0].domain, "a_dom");
    EXPECT_EQ(set.domains[0].allows,
              (std::vector<std::string>{"allow a_dom x:dir search;", "allow a_dom y:file read;"}));
}

TEST(RuleGenTest, SelfTarget) {
    NoTypes types;
    auto set = GenerateRules({T("a_dom", "a_dom", "process", {"setsched"})}, types, nullptr);
    EXPECT_EQ(Find(set, "a_dom").allows,
              (std::vector<std::string>{"allow a_dom self:process setsched;"}));
}

TEST(RuleGenTest, IoctlsBecomeAllowxperm) {
    NoTypes types;
    Tuple t = T("a_dom", "foo_device", "chr_file", {"ioctl", "open"});
    t.ioctls = {"0x5401", "0x540", "0x1"};
    auto set = GenerateRules({t}, types, nullptr);
    const DomainRules& rules = Find(set, "a_dom");
    EXPECT_EQ(rules.allows,
              (std::vector<std::string>{"allow a_dom foo_device:chr_file { ioctl open };"}));
    EXPECT_EQ(rules.xperms,
              (std::vector<std::string>{
                      "allowxperm a_dom foo_device:chr_file ioctl { 0x1 0x540 0x5401 };"}));
}

TEST(RuleGenTest, IoctlWithoutCommandIsFlagged) {
    NoTypes types;
    auto set = GenerateRules({T("a_dom", "foo_device", "chr_file", {"ioctl"})}, types, nullptr);
    EXPECT_TRUE(NoteMentions(set, "without a command number"));
}

TEST(RuleGenTest, UnlabeledTargetsAreWithheld) {
    NoTypes types;
    auto set = GenerateRules({T("a_dom", "unlabeled", "file", {"read"})}, types, nullptr);
    const DomainRules& rules = Find(set, "a_dom");
    EXPECT_TRUE(rules.allows.empty());
    EXPECT_EQ(rules.withheld, (std::vector<std::string>{"# allow a_dom unlabeled:file read;"}));
    EXPECT_TRUE(NoteMentions(set, "no label"));
}

TEST(RuleGenTest, RiskyPermissionsAreNoted) {
    NoTypes types;
    auto set = GenerateRules({T("a_dom", "a_dom", "capability", {"sys_admin"})}, types, nullptr);
    EXPECT_TRUE(NoteMentions(set, "CAP_SYS_ADMIN"));
    // Still emitted: it is a note, not a veto.
    EXPECT_EQ(Find(set, "a_dom").allows.size(), 1u);
}

TEST(RuleGenTest, PrivatePlatformTargetsAreWithheldFromVendorPolicy) {
    PolicyDb db("202604");
    db.AddCil("(type pub_type) (type priv_type) (type some_domain)", PolicyOrigin::kPlatform);
    db.AddCil("(type hal_foo) (typeattributeset file_type (pub_type_202604))",
              PolicyOrigin::kVendor);
    NoTypes types;

    auto set = GenerateRules({T("hal_foo", "pub_type", "file", {"read"}),
                              T("hal_foo", "priv_type", "file", {"read"})},
                             types, &db);
    const DomainRules& rules = Find(set, "hal_foo");
    EXPECT_EQ(rules.home, RuleHome::kVendor);
    EXPECT_EQ(rules.allows, (std::vector<std::string>{"allow hal_foo pub_type:file read;"}));
    EXPECT_EQ(rules.withheld, (std::vector<std::string>{"# allow hal_foo priv_type:file read;"}));
    EXPECT_TRUE(NoteMentions(set, "private platform type"));
}

TEST(RuleGenTest, PrivatePlatformDomainsGoToThePlatform) {
    PolicyDb db("202604");
    db.AddCil("(type pub_type) (type priv_domain)", PolicyOrigin::kPlatform);
    db.AddCil("(type hal_foo) (typeattributeset file_type (pub_type_202604))",
              PolicyOrigin::kVendor);
    NoTypes types;
    auto set = GenerateRules({T("priv_domain", "pub_type", "file", {"read"})}, types, &db);
    EXPECT_EQ(Find(set, "priv_domain").home, RuleHome::kPlatform);
}

TEST(RuleGenTest, MacrosReplaceTheRulesTheyCover) {
    class Props : public TypeInfo {
      public:
        bool HasAttribute(const std::string& t, const std::string& a) const override {
            return t == "vendor_foo_prop" && a == "property_type";
        }
    } types;
    auto set = GenerateRules({T("a_dom", "vendor_foo_prop", "file", {"read", "open", "write"})},
                             types, nullptr);
    const DomainRules& rules = Find(set, "a_dom");
    EXPECT_EQ(rules.macros, (std::vector<std::string>{"get_prop(a_dom, vendor_foo_prop)"}));
    // What the macro does not grant is still written out.
    EXPECT_EQ(rules.allows, (std::vector<std::string>{"allow a_dom vendor_foo_prop:file write;"}));
}

TEST(RuleGenTest, VendorDomainsDoNotGetReadLogd) {
    class Logd : public TypeInfo {
      public:
        bool HasAttribute(const std::string& t, const std::string& a) const override {
            return t == "logd" && a == "domain";
        }
    } types;
    PolicyDb db("202604");
    db.AddCil("(type logd)", PolicyOrigin::kPlatform);
    db.AddCil("(type hal_foo)", PolicyOrigin::kVendor);
    std::vector<Tuple> tuples = {T("hal_foo", "logd", "unix_stream_socket", {"connectto"}),
                                 T("hal_foo", "logdr_socket", "sock_file", {"write"})};
    auto set = GenerateRules(tuples, types, &db);
    EXPECT_EQ(Find(set, "hal_foo").macros,
              (std::vector<std::string>{"unix_socket_connect(hal_foo, logdr, logd)"}));
}

}  // namespace selogger
