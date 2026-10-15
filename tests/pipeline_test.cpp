/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "analyze/policy_db.h"
#include "analyze/report.h"
#include "analyze/type_info.h"
#include "label/labeler.h"

namespace selogger {

namespace {

class NoDevice : public DeviceInfo {
  public:
    std::string FileLabel(const std::string&, const std::string&) const override { return ""; }
    std::string PropertyLabel(const std::string&) const override { return ""; }
    std::string ServiceLabel(ServiceKind, const std::string&) const override { return ""; }
    std::vector<std::string> PropertiesLabeled(const std::string&) const override { return {}; }
    std::string ResolveInode(const std::string&, uint64_t, const std::string&) const override {
        return "";
    }
    std::string RealPath(const std::string& path) const override { return path; }
    std::string MountPoint(const std::string&) const override { return ""; }
    std::vector<std::string> FindExecutables(const std::string&) const override { return {}; }
};

}  // namespace

// Audit lines in, files out: the whole path of "selogger dump" except the
// parts that ask the device.
TEST(PipelineTest, AuditLinesToPolicyFiles) {
    const char* const kLines[] = {
            "type=1400 audit(0.0:1): avc:  denied  { set } for property=vendor.foo.mode "
            "scontext=u:r:hal_foo:s0 tcontext=u:object_r:vendor_default_prop:s0 "
            "tclass=property_service permissive=0",
            "type=1400 audit(0.0:2): avc:  denied  { read open } for  comm=\"foo\" "
            "path=\"/vendor/etc/foo.cfg\" dev=\"dm-4\" ino=7 scontext=u:r:hal_foo:s0 "
            "tcontext=u:object_r:vendor_file:s0 tclass=file permissive=0",
            "type=1400 audit(0.0:3): avc:  denied  { read open } for  comm=\"foo\" "
            "path=\"/vendor/etc/foo.cfg\" dev=\"dm-4\" ino=7 scontext=u:r:hal_foo:s0 "
            "tcontext=u:object_r:vendor_file:s0 tclass=file permissive=0",
            "type=1400 audit(0.0:4): avc:  denied  { find } for  name=vendor.x.IFoo/default "
            "scontext=u:r:hal_foo:s0 tcontext=u:object_r:default_android_service:s0 "
            "tclass=service_manager permissive=0",
            "type=1400 audit(0.0:5): avc:  denied  { call } for  scontext=u:r:hal_foo:s0 "
            "tcontext=u:r:servicemanager:s0 tclass=binder permissive=0",
            "type=1400 audit(0.0:6): avc:  denied  { read } for  comm=\"bar\" "
            "scontext=u:r:hal_bar:s0 tcontext=u:object_r:unlabeled:s0 tclass=file permissive=0",
    };

    PolicyDb policy("202604");
    policy.AddCil(
            "(type servicemanager) (type vendor_file) (typeattributeset domain (servicemanager))",
            PolicyOrigin::kPlatform);
    policy.AddCil(
            "(type hal_foo) (type hal_bar) (typeattributeset domain (hal_foo hal_bar)) "
            "(typeattributeset file_type (vendor_file_202604 servicemanager_202604))",
            PolicyOrigin::kVendor);

    TupleTable table(1000, 16);
    for (const char* line : kLines) {
        auto denial = ParseAvc(line);
        ASSERT_TRUE(denial.has_value()) << line;
        table.Add(*denial, {100, "boot"});
    }
    std::vector<Tuple> collected;
    for (const auto& [key, tuple] : table.tuples()) collected.push_back(tuple);

    NoDevice device;
    LabelResult labels = RunLabelers(collected, device, &policy);
    PolicyTypes types(&policy, labels.plan.new_types);
    RuleSet rules = GenerateRules(labels.tuples, types, &policy);
    auto files = BuildOutputFiles({collected, labels.plan, rules, 3});

    // hal_foo: a property, a file, a service and the service manager.
    const std::string& foo = files.at("vendor/hal_foo.te");
    EXPECT_NE(foo.find("set_prop(hal_foo, vendor_foo_mode_prop)"), std::string::npos) << foo;
    EXPECT_NE(foo.find("binder_use(hal_foo)"), std::string::npos) << foo;
    EXPECT_NE(foo.find("allow hal_foo foo_cfg_vendor_file:file { open read };"), std::string::npos)
            << foo;
    EXPECT_NE(foo.find("allow hal_foo hal_vendor_x_ifoo_service:service_manager find;"),
              std::string::npos)
            << foo;
    // Nothing is allowed on the fallback types themselves.
    EXPECT_EQ(foo.find("vendor_default_prop"), std::string::npos) << foo;
    EXPECT_EQ(foo.find("allow hal_foo vendor_file"), std::string::npos) << foo;

    EXPECT_NE(files.at("vendor/property_contexts")
                      .find("vendor.foo.mode u:object_r:vendor_foo_mode_prop:s0 exact"),
              std::string::npos);
    EXPECT_NE(files.at("vendor/file_contexts")
                      .find("/vendor/etc/foo\\.cfg u:object_r:foo_cfg_vendor_file:s0"),
              std::string::npos);
    EXPECT_NE(files.at("vendor/service_contexts")
                      .find("vendor.x.IFoo/default u:object_r:hal_vendor_x_ifoo_service:s0"),
              std::string::npos);

    // hal_bar: the unlabeled target is withheld, not allowed.
    const std::string& bar = files.at("vendor/hal_bar.te");
    EXPECT_NE(bar.find("# Withheld\n# allow hal_bar unlabeled:file read;"), std::string::npos)
            << bar;
    EXPECT_EQ(bar.find("\nallow hal_bar"), std::string::npos) << bar;

    const std::string& review = files.at("REVIEW.md");
    EXPECT_NE(review.find("dropped 3 audit messages"), std::string::npos);
    EXPECT_NE(review.find("no label"), std::string::npos);
    EXPECT_NE(review.find("| 2 | hal_foo -> vendor_file:file"), std::string::npos) << review;
}

}  // namespace selogger
