/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "analyze/report.h"
#include "label/contexts.h"

namespace selogger {

namespace {

Tuple T(const std::string& stype, const std::string& ttype, const std::string& tclass,
        std::set<std::string> perms, uint64_t count = 1) {
    Tuple t;
    t.key = {stype, ttype, tclass};
    t.perms = std::move(perms);
    t.count = count;
    t.saw_enforcing = true;
    return t;
}

}  // namespace

TEST(ReportTest, WritesOneFilePerDomainWithSections) {
    std::vector<Tuple> collected = {T("hal_foo", "vendor_file", "file", {"read"}, 5)};
    LabelPlan labels;
    labels.AddLine("vendor/file_contexts", "/vendor/etc/a u:object_r:a_file:s0");
    labels.AddDomainLine("hal_foo", "hal_attribute_service(hal_foo, x_service)");
    RuleSet rules;
    DomainRules d;
    d.domain = "hal_foo";
    d.macros = {"get_prop(hal_foo, vendor_x_prop)"};
    d.allows = {"allow hal_foo vendor_file:file read;"};
    d.xperms = {"allowxperm hal_foo d:chr_file ioctl { 0x1 };"};
    d.withheld = {"# allow hal_foo unlabeled:file read;"};
    rules.domains.push_back(d);

    auto files = BuildOutputFiles({collected, labels, rules, 0});
    ASSERT_TRUE(files.contains("vendor/hal_foo.te"));
    const std::string& te = files.at("vendor/hal_foo.te");
    EXPECT_NE(te.find("# Declarations\nhal_attribute_service(hal_foo, x_service)"),
              std::string::npos);
    EXPECT_NE(te.find("# Macros\nget_prop(hal_foo, vendor_x_prop)"), std::string::npos);
    EXPECT_NE(te.find("# Rules\nallow hal_foo vendor_file:file read;"), std::string::npos);
    EXPECT_NE(te.find("# Extended permissions\nallowxperm"), std::string::npos);
    EXPECT_NE(te.find("# Withheld\n# allow hal_foo unlabeled"), std::string::npos);
    EXPECT_EQ(files.at("vendor/file_contexts"),
              "# Added by selogger\n/vendor/etc/a u:object_r:a_file:s0\n");
}

TEST(ReportTest, PlatformDomainsAndDeclarationOnlyDomains) {
    std::vector<Tuple> collected;
    LabelPlan labels;
    labels.AddDomainLine("new_daemon", "init_daemon_domain(new_daemon)");
    RuleSet rules;
    DomainRules d;
    d.domain = "priv";
    d.home = RuleHome::kPlatform;
    d.allows = {"allow priv x:file read;"};
    rules.domains.push_back(d);

    auto files = BuildOutputFiles({collected, labels, rules, 0});
    EXPECT_TRUE(files.contains("platform/priv.te"));
    ASSERT_TRUE(files.contains("vendor/new_daemon.te"));
    EXPECT_NE(files.at("vendor/new_daemon.te").find("init_daemon_domain(new_daemon)"),
              std::string::npos);
}

TEST(ReportTest, ReviewSummarizesNotesAndLoss) {
    std::vector<Tuple> collected = {T("a", "b", "file", {"read"}, 3),
                                    T("a", "c", "file", {"write"}, 90)};
    LabelPlan labels;
    labels.notes.push_back({"a", "label note"});
    RuleSet rules;
    rules.notes.push_back({"a", "rule note"});
    rules.notes.push_back({"a", "rule note"});  // duplicates collapse

    std::string review = BuildOutputFiles({collected, labels, rules, 42}).at("REVIEW.md");
    EXPECT_NE(review.find("2 kinds of denials (93 in total) from 1 domains"), std::string::npos);
    EXPECT_NE(review.find("The kernel dropped 42 audit messages"), std::string::npos);
    EXPECT_NE(review.find("### a\n\n- label note\n- rule note\n"), std::string::npos);
    // The most frequent one comes first.
    EXPECT_LT(review.find("a -> c:file"), review.find("a -> b:file"));
}

TEST(ReportTest, NoLossLineWithoutLoss) {
    LabelPlan labels;
    RuleSet rules;
    std::string review = BuildOutputFiles({{}, labels, rules, 0}).at("REVIEW.md");
    EXPECT_EQ(review.find("dropped"), std::string::npos);
}

TEST(ReportTest, FormatTuplesIsSortedAndShowsHints) {
    Tuple t = T("b", "x", "file", {"read"}, 2);
    t.hints[kHintPath] = {"/p"};
    std::string out = FormatTuples({t, T("a", "x", "file", {"write"})});
    EXPECT_EQ(out, "1x a -> x:file { write }\n2x b -> x:file { read } path=/p\n");
}

TEST(ContextsTest, ServiceLookupIsExact) {
    ServiceContexts contexts;
    contexts.Add(
            "#line 1 \"x\"\n# comment\n\nfoo.IBar/default  u:object_r:foo_service:s0\n"
            "other u:object_r:other_service:s0\n"
            "foo.IBar/default u:object_r:ignored:s0\n");
    EXPECT_EQ(contexts.Lookup("foo.IBar/default"), "foo_service");
    EXPECT_EQ(contexts.Lookup("foo.IBar"), "");
    EXPECT_EQ(contexts.Lookup("other"), "other_service");
}

TEST(ContextsTest, PropertyLookupPrefixExactAndLongest) {
    PropertyContexts contexts;
    contexts.Add(
            "vendor.        u:object_r:vendor_default_prop:s0\n"
            "vendor.foo.    u:object_r:vendor_foo_prop:s0 string\n"
            "vendor.foo.bar u:object_r:vendor_foo_bar_prop:s0 exact bool\n"
            "# comment\n");
    EXPECT_EQ(contexts.Lookup("vendor.x"), "vendor_default_prop");
    EXPECT_EQ(contexts.Lookup("vendor.foo.baz"), "vendor_foo_prop");
    EXPECT_EQ(contexts.Lookup("vendor.foo.bar"), "vendor_foo_bar_prop");
    EXPECT_EQ(contexts.Lookup("vendor.foo.barn"), "vendor_foo_prop");  // exact does not extend
    EXPECT_EQ(contexts.Lookup("ro.x"), "");
}

}  // namespace selogger
