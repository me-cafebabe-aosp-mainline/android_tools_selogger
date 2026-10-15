/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "label/labeler.h"

namespace selogger {

namespace {

class FakeDevice : public DeviceInfo {
  public:
    std::map<std::string, std::string> file_labels;      // path -> type
    std::map<std::string, std::string> property_labels;  // name -> type
    std::map<std::string, std::string> service_labels;   // name -> type
    std::map<std::string, std::vector<std::string>> properties_of_type;
    std::map<std::string, std::string> inodes;  // "dev:ino" -> path
    std::map<std::string, std::string> real_paths;
    std::map<std::string, std::vector<std::string>> executables;

    std::string FileLabel(const std::string& path, const std::string&) const override {
        auto it = file_labels.find(path);
        return it == file_labels.end() ? "" : it->second;
    }
    std::string PropertyLabel(const std::string& name) const override {
        auto it = property_labels.find(name);
        return it == property_labels.end() ? "" : it->second;
    }
    std::string ServiceLabel(ServiceKind, const std::string& name) const override {
        auto it = service_labels.find(name);
        return it == service_labels.end() ? "" : it->second;
    }
    std::vector<std::string> PropertiesLabeled(const std::string& type) const override {
        auto it = properties_of_type.find(type);
        return it == properties_of_type.end() ? std::vector<std::string>{} : it->second;
    }
    std::string ResolveInode(const std::string& dev, uint64_t ino,
                             const std::string&) const override {
        auto it = inodes.find(dev + ":" + std::to_string(ino));
        return it == inodes.end() ? "" : it->second;
    }
    std::string RealPath(const std::string& path) const override {
        auto it = real_paths.find(path);
        return it == real_paths.end() ? path : it->second;
    }
    std::string MountPoint(const std::string&) const override { return ""; }
    std::vector<std::string> FindExecutables(const std::string& comm) const override {
        auto it = executables.find(comm);
        return it == executables.end() ? std::vector<std::string>{} : it->second;
    }
};

Tuple T(const std::string& stype, const std::string& ttype, const std::string& tclass,
        std::set<std::string> perms, std::map<std::string, std::set<std::string>> hints = {}) {
    Tuple t;
    t.key = {stype, ttype, tclass};
    t.perms = std::move(perms);
    t.hints = std::move(hints);
    t.count = 1;
    return t;
}

bool Has(const LabelPlan& plan, const std::string& file, const std::string& line) {
    auto it = plan.files.find(file);
    if (it == plan.files.end()) return false;
    return std::find(it->second.begin(), it->second.end(), line) != it->second.end();
}

bool NoteMentions(const LabelPlan& plan, const std::string& text) {
    for (const ReviewNote& n : plan.notes) {
        if (n.text.find(text) != std::string::npos) return true;
    }
    return false;
}

const Tuple* Find(const std::vector<Tuple>& tuples, const TupleKey& key) {
    for (const Tuple& t : tuples) {
        if (t.key == key) return &t;
    }
    return nullptr;
}

}  // namespace

TEST(LabelHelpersTest, SanitizeEscapeCollapse) {
    EXPECT_EQ(SanitizeName("foo.bar-Baz"), "foo_bar_baz");
    EXPECT_EQ(SanitizeName("..a..b.."), "a_b");
    EXPECT_EQ(SanitizeName("9lives"), "x9lives");
    EXPECT_EQ(SanitizeName("..."), "x");
    EXPECT_EQ(EscapeRegex("/vendor/lib/a.so"), "/vendor/lib/a\\.so");
    EXPECT_EQ(CollapseSiblings({"/a/x", "/a/y", "/b/z"}, 3),
              (std::vector<std::string>{"/a/x", "/a/y", "/b/z"}));
    EXPECT_EQ(CollapseSiblings({"/a/x", "/a/y", "/a/z", "/b/z"}, 3),
              (std::vector<std::string>{"/a", "/b/z"}));
}

TEST(LabelPropertiesTest, NewPropertyGetsTypeAndContext) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "default_prop", "property_service", {"set"},
                                   {{kHintProperty, {"vendor.foo.mode"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/property_contexts",
                    "vendor.foo.mode u:object_r:vendor_foo_mode_prop:s0 exact"));
    EXPECT_TRUE(
            Has(result.plan, "vendor/property.te", "vendor_internal_prop(vendor_foo_mode_prop)"));
    EXPECT_TRUE(result.plan.new_types.at("vendor_foo_mode_prop").contains("property_type"));
    ASSERT_EQ(result.tuples.size(), 1u);
    EXPECT_EQ(result.tuples[0].key.ttype, "vendor_foo_mode_prop");
    EXPECT_EQ(result.tuples[0].perms, (std::set<std::string>{"set"}));
}

TEST(LabelPropertiesTest, RoVendorPrefixIsStripped) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "vendor_default_prop", "property_service", {"set"},
                                   {{kHintProperty, {"ro.vendor.foo.bar"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/property_contexts",
                    "ro.vendor.foo.bar u:object_r:vendor_foo_bar_prop:s0 exact"));
}

TEST(LabelPropertiesTest, NonVendorNamesGoToThePlatformWithANote) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "default_prop", "property_service", {"set"},
                                   {{kHintProperty, {"sys.foo.state"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "platform/property_contexts",
                    "sys.foo.state u:object_r:vendor_sys_foo_state_prop:s0 exact"));
    EXPECT_TRUE(NoteMentions(result.plan, "outside the vendor property namespaces"));
}

TEST(LabelPropertiesTest, SpecificTargetsAreLeftAlone) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "vendor_foo_prop", "property_service", {"set"},
                                   {{kHintProperty, {"vendor.foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(result.plan.files.empty());
    EXPECT_EQ(result.tuples[0].key.ttype, "vendor_foo_prop");
}

TEST(LabelPropertiesTest, CtlPropertiesAreOnlyNoted) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "default_prop", "property_service", {"set"},
                                   {{kHintProperty, {"ctl.start$foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(result.plan.files.empty());
    EXPECT_TRUE(NoteMentions(result.plan, "ctl_*_prop"));
}

TEST(LabelPropertiesTest, ReadsListTheCandidates) {
    FakeDevice device;
    device.properties_of_type["vendor_default_prop"] = {"vendor.a", "vendor.b"};
    std::vector<Tuple> tuples = {T("hal_foo", "vendor_default_prop", "file", {"read"})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(NoteMentions(result.plan, "vendor.a, vendor.b"));
}

TEST(LabelServicesTest, AidlServiceGetsTypeAndContext) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo_default", "default_android_service", "service_manager",
                                   {"add", "find"},
                                   {{kHintService, {"android.hardware.foo.IFoo/default"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/service_contexts",
                    "android.hardware.foo.IFoo/default u:object_r:hal_foo_ifoo_service:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/service.te",
                    "type hal_foo_ifoo_service, hal_service_type, service_manager_type;"));
    ASSERT_EQ(result.tuples.size(), 1u);
    EXPECT_EQ(result.tuples[0].key.ttype, "hal_foo_ifoo_service");
}

TEST(LabelServicesTest, InstancesOfOneInterfaceShareTheType) {
    FakeDevice device;
    std::vector<Tuple> tuples = {
            T("hal_foo_default", "default_android_service", "service_manager", {"add"},
              {{kHintService, {"vendor.x.IFoo/default", "vendor.x.IFoo/slot1"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/service_contexts",
                    "vendor.x.IFoo/default u:object_r:hal_vendor_x_ifoo_service:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/service_contexts",
                    "vendor.x.IFoo/slot1 u:object_r:hal_vendor_x_ifoo_service:s0"));
    EXPECT_EQ(result.plan.new_types.size(), 1u);
}

TEST(LabelServicesTest, HalServersUseTheAttributePair) {
    PolicyDb db("202604");
    db.AddCil(
            "(type hal_foo_default) (typeattribute hal_foo_server) (typeattributeset "
            "hal_foo_server (hal_foo_default))",
            PolicyOrigin::kVendor);
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo_default", "default_android_service", "service_manager",
                                   {"add"}, {{kHintService, {"vendor.x.IFoo/default"}}})};
    LabelResult result = RunLabelers(tuples, device, &db);
    ASSERT_TRUE(result.plan.domain_lines.contains("hal_foo_default"));
    EXPECT_EQ(result.plan.domain_lines.at("hal_foo_default"),
              (std::vector<std::string>{
                      "hal_attribute_service(hal_foo, hal_vendor_x_ifoo_service)"}));
    // The macro covers add and find, so no rule is left.
    EXPECT_TRUE(result.tuples.empty());
}

TEST(LabelServicesTest, HwServicesAndVndServices) {
    FakeDevice device;
    std::vector<Tuple> tuples = {
            T("hal_foo", "default_android_hwservice", "hwservice_manager", {"find"},
              {{kHintHwService, {"android.hardware.foo@1.0::IFoo"}}}),
            T("some_app_daemon", "default_android_vndservice", "service_manager", {"add"},
              {{kHintService, {"my.vnd.service"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/hwservice_contexts",
                    "android.hardware.foo@1.0::IFoo u:object_r:hal_foo_1_0_ifoo_hwservice:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/vndservice_contexts",
                    "my.vnd.service u:object_r:my_vnd_service_service:s0"));
    EXPECT_TRUE(
            result.plan.new_types.at("my_vnd_service_service").contains("vndservice_manager_type"));
}

TEST(LabelServicesTest, ExistingSpecificLabelIsLeftAlone) {
    FakeDevice device;
    device.service_labels["foo"] = "foo_service";
    std::vector<Tuple> tuples = {T("a", "default_android_service", "service_manager", {"find"},
                                   {{kHintService, {"foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(result.plan.files.empty());
    EXPECT_TRUE(NoteMentions(result.plan, "foo_service"));
}

TEST(LabelFilesTest, VendorFileGetsALabel) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "vendor_file", "file", {"read", "open"},
                                   {{kHintPath, {"/vendor/etc/foo.bin"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/vendor/etc/foo\\.bin u:object_r:foo_bin_vendor_file:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/file.te",
                    "type foo_bin_vendor_file, file_type, vendor_file_type;"));
    ASSERT_EQ(result.tuples.size(), 1u);
    EXPECT_EQ(result.tuples[0].key.ttype, "foo_bin_vendor_file");
}

TEST(LabelFilesTest, DeviceNodesAndSockets) {
    FakeDevice device;
    std::vector<Tuple> tuples = {
            T("hal_foo", "device", "chr_file", {"read"}, {{kHintPath, {"/dev/foo0"}}}),
            T("hal_foo", "device", "sock_file", {"write"}, {{kHintPath, {"/dev/socket/foosock"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts", "/dev/foo0 u:object_r:foo0_device:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/file.te", "type foo0_device, dev_type;"));
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/dev/socket/foosock u:object_r:foosock_socket:s0"));
}

TEST(LabelFilesTest, ExecutablesAndDataDirectories) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("init", "vendor_file", "file", {"execute"},
                                   {{kHintPath, {"/vendor/bin/hw/foo-service"}}}),
                                 T("hal_foo", "vendor_data_file", "dir", {"search"},
                                   {{kHintPath, {"/data/vendor/foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/vendor/bin/hw/foo-service u:object_r:foo_service_exec:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/file.te",
                    "type foo_service_exec, exec_type, file_type, vendor_file_type;"));
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/data/vendor/foo(/.*)? u:object_r:foo_data_file:s0"));
}

TEST(LabelFilesTest, SiblingsCollapseIntoTheirDirectory) {
    FakeDevice device;
    std::vector<Tuple> tuples = {
            T("hal_foo", "vendor_file", "file", {"read"},
              {{kHintPath,
                {"/vendor/firmware/a.bin", "/vendor/firmware/b.bin", "/vendor/firmware/c.bin"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/vendor/firmware(/.*)? u:object_r:firmware_vendor_file:s0"));
    EXPECT_EQ(result.plan.files.at("vendor/file_contexts").size(), 1u);
}

TEST(LabelFilesTest, ExistingSpecificLabelMeansRelabel) {
    FakeDevice device;
    device.file_labels["/vendor/etc/foo.bin"] = "foo_file";
    std::vector<Tuple> tuples = {
            T("hal_foo", "vendor_file", "file", {"read"}, {{kHintPath, {"/vendor/etc/foo.bin"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(result.plan.files.empty());
    EXPECT_TRUE(NoteMentions(result.plan, "restorecon"));
    // The denial stays as it is: nothing was proposed.
    EXPECT_EQ(result.tuples[0].key.ttype, "vendor_file");
}

TEST(LabelFilesTest, SysfsNodesGetGenfscon) {
    PolicyDb db("202604");
    db.AddCil("(type sysfs) (typeattribute sysfs_type) (typeattribute fs_type)",
              PolicyOrigin::kPlatform);
    FakeDevice device;
    device.real_paths["/sys/class/foo/mode"] = "/sys/devices/platform/foo/mode";
    std::vector<Tuple> tuples = {T("hal_foo", "sysfs", "file", {"read", "write", "open"},
                                   {{kHintPath, {"/sys/class/foo/mode"}}})};
    LabelResult result = RunLabelers(tuples, device, &db);
    EXPECT_TRUE(Has(result.plan, "vendor/genfs_contexts",
                    "genfscon sysfs /devices/platform/foo/mode u:object_r:vendor_sysfs_mode:s0"));
    EXPECT_TRUE(Has(result.plan, "vendor/file.te", "type vendor_sysfs_mode, fs_type, sysfs_type;"));
    EXPECT_EQ(result.tuples[0].key.ttype, "vendor_sysfs_mode");
}

TEST(LabelFilesTest, ExistingGenfsLabelIsLeftAlone) {
    PolicyDb db("202604");
    db.AddCil(
            "(type sysfs) (genfscon sysfs \"/devices/platform/foo\" (u object_r sysfs_foo ((s0) "
            "(s0))))",
            PolicyOrigin::kPlatform);
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "sysfs", "file", {"read"},
                                   {{kHintPath, {"/sys/devices/platform/foo/mode"}}})};
    LabelResult result = RunLabelers(tuples, device, &db);
    EXPECT_TRUE(result.plan.files.empty());
    EXPECT_TRUE(NoteMentions(result.plan, "already has genfscon label sysfs_foo"));
}

TEST(LabelFilesTest, InodesAreResolvedAndPerProcessPathsSkipped) {
    FakeDevice device;
    device.inodes["dm-4:77"] = "/vendor/etc/found.cfg";
    std::vector<Tuple> tuples = {
            T("hal_foo", "vendor_file", "file", {"read"}, {{kHintDevIno, {"dm-4:77:found.cfg"}}}),
            T("hal_foo", "proc", "file", {"read"}, {{kHintPath, {"/proc/1234/maps"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/vendor/etc/found\\.cfg u:object_r:found_cfg_vendor_file:s0"));
    EXPECT_FALSE(result.plan.files.contains("vendor/genfs_contexts"));
}

TEST(LabelFilesTest, DenialsWithoutAPathAreNoted) {
    FakeDevice device;
    std::vector<Tuple> tuples = {T("hal_foo", "vendor_file", "file", {"read"})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(NoteMentions(result.plan, "without a path"));
}

TEST(LabelFilesTest, CreateDenialsSuggestATransition) {
    FakeDevice device;
    std::vector<Tuple> tuples = {
            T("hal_foo", "vendor_data_file", "file", {"create"}, {{kHintName, {"state.db"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(NoteMentions(result.plan, "file_type_auto_trans(hal_foo, vendor_data_file"));
}

TEST(LabelInitDaemonsTest, DaemonRunningInInitGetsADomain) {
    FakeDevice device;
    device.executables["foo-daemon"] = {"/vendor/bin/foo-daemon"};
    std::vector<Tuple> tuples = {
            T("init", "vendor_data_file", "dir", {"search"},
              {{kHintComm, {"foo-daemon"}}, {kHintPath, {"/data/vendor/foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/vendor/bin/foo-daemon u:object_r:foo_daemon_exec:s0"));
    EXPECT_EQ(result.plan.domain_lines.at("foo_daemon"),
              (std::vector<std::string>{
                      "type foo_daemon, domain;",
                      "type foo_daemon_exec, exec_type, vendor_file_type, file_type;",
                      "init_daemon_domain(foo_daemon)"}));
    // The denial is now the daemon's, and the later labelers saw it that way.
    EXPECT_EQ(result.tuples[0].key.stype, "foo_daemon");
    EXPECT_TRUE(Has(result.plan, "vendor/file_contexts",
                    "/data/vendor/foo(/.*)? u:object_r:foo_data_file:s0"));
}

TEST(LabelInitDaemonsTest, InitsOwnDenialsStay) {
    FakeDevice device;
    std::vector<Tuple> tuples = {
            T("init", "vendor_file", "file", {"read"}, {{kHintComm, {"init"}}}),
            T("init", "vendor_file", "dir", {"read"}, {{kHintComm, {"init", "foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(result.plan.domain_lines.empty());
    EXPECT_NE(Find(result.tuples, {"init", "vendor_file", "file"}), nullptr);
}

TEST(LabelInitDaemonsTest, AmbiguousExecutableIsNotedNotGuessed) {
    FakeDevice device;
    device.executables["foo"] = {"/vendor/bin/foo", "/vendor/bin/foo2"};
    std::vector<Tuple> tuples = {
            T("init", "vendor_file", "file", {"read"}, {{kHintComm, {"foo"}}})};
    LabelResult result = RunLabelers(tuples, device, nullptr);
    EXPECT_TRUE(result.plan.domain_lines.empty());
    EXPECT_TRUE(NoteMentions(result.plan, "2 executables"));
    EXPECT_EQ(result.tuples[0].key.stype, "init");
}

}  // namespace selogger
