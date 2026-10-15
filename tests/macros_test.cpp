/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "analyze/macros.h"

namespace selogger {

namespace {

// Attributes by hand.
class FakeTypes : public TypeInfo {
  public:
    std::map<std::string, std::set<std::string>> attrs;

    bool HasAttribute(const std::string& type, const std::string& attribute) const override {
        auto it = attrs.find(type);
        return it != attrs.end() && it->second.contains(attribute);
    }
};

Tuple T(const std::string& ttype, const std::string& tclass, std::set<std::string> perms,
        const std::string& stype = "hal_foo") {
    Tuple t;
    t.key = {stype, ttype, tclass};
    t.perms = std::move(perms);
    return t;
}

std::vector<const Tuple*> Ptrs(const std::vector<Tuple>& tuples) {
    std::vector<const Tuple*> out;
    for (const Tuple& t : tuples) out.push_back(&t);
    return out;
}

std::vector<std::string> Texts(const std::vector<MacroUse>& uses) {
    std::vector<std::string> out;
    for (const MacroUse& use : uses) out.push_back(use.text);
    return out;
}

}  // namespace

TEST(MacrosTest, GetPropForPropertyReads) {
    FakeTypes types;
    types.attrs["vendor_foo_prop"] = {"property_type"};
    std::vector<Tuple> tuples = {T("vendor_foo_prop", "file", {"read", "open"})};
    auto uses = MatchMacros("hal_foo", Ptrs(tuples), types);
    EXPECT_EQ(Texts(uses), (std::vector<std::string>{"get_prop(hal_foo, vendor_foo_prop)"}));
}

TEST(MacrosTest, ReadOfANonPropertyFileIsNotGetProp) {
    FakeTypes types;
    types.attrs["vendor_file"] = {"file_type"};
    std::vector<Tuple> tuples = {T("vendor_file", "file", {"read"})};
    EXPECT_TRUE(MatchMacros("hal_foo", Ptrs(tuples), types).empty());
}

TEST(MacrosTest, SetPropCoversTheReadToo) {
    FakeTypes types;
    types.attrs["vendor_foo_prop"] = {"property_type"};
    std::vector<Tuple> tuples = {T("vendor_foo_prop", "property_service", {"set"}),
                                 T("vendor_foo_prop", "file", {"read", "open"})};
    auto uses = MatchMacros("hal_foo", Ptrs(tuples), types);
    EXPECT_EQ(Texts(uses), (std::vector<std::string>{"set_prop(hal_foo, vendor_foo_prop)"}));
    // Both denials are explained by the one macro.
    EXPECT_EQ(uses[0].covered.size(), 2u);
}

TEST(MacrosTest, UnixSocketConnectNeedsBothHalves) {
    FakeTypes types;
    types.attrs["foo_server"] = {"domain"};
    std::vector<Tuple> connect_only = {T("foo_server", "unix_stream_socket", {"connectto"})};
    EXPECT_TRUE(MatchMacros("hal_foo", Ptrs(connect_only), types).empty());

    std::vector<Tuple> both = {T("foo_server", "unix_stream_socket", {"connectto"}),
                               T("foo_socket", "sock_file", {"write"})};
    EXPECT_EQ(Texts(MatchMacros("hal_foo", Ptrs(both), types)),
              (std::vector<std::string>{"unix_socket_connect(hal_foo, foo, foo_server)"}));
}

TEST(MacrosTest, ReadLogdBeatsTheGenericSocketMacro) {
    FakeTypes types;
    types.attrs["logd"] = {"domain"};
    std::vector<Tuple> tuples = {T("logd", "unix_stream_socket", {"connectto"}),
                                 T("logdr_socket", "sock_file", {"write"})};
    EXPECT_EQ(Texts(MatchMacros("hal_foo", Ptrs(tuples), types)),
              (std::vector<std::string>{"read_logd(hal_foo)"}));
}

TEST(MacrosTest, BinderUseBeatsBinderCall) {
    FakeTypes types;
    types.attrs["servicemanager"] = {"domain"};
    std::vector<Tuple> tuples = {T("servicemanager", "binder", {"call"})};
    EXPECT_EQ(Texts(MatchMacros("hal_foo", Ptrs(tuples), types)),
              (std::vector<std::string>{"binder_use(hal_foo)"}));

    types.attrs["some_server"] = {"domain"};
    std::vector<Tuple> other = {T("some_server", "binder", {"call"})};
    EXPECT_EQ(Texts(MatchMacros("hal_foo", Ptrs(other), types)),
              (std::vector<std::string>{"binder_call(hal_foo, some_server)"}));
}

TEST(MacrosTest, AddServiceNeedsTheAddPermission) {
    FakeTypes types;
    types.attrs["foo_service"] = {"service_manager_type"};
    std::vector<Tuple> find = {T("foo_service", "service_manager", {"find"})};
    EXPECT_TRUE(MatchMacros("hal_foo", Ptrs(find), types).empty());
    std::vector<Tuple> add = {T("foo_service", "service_manager", {"add"})};
    EXPECT_EQ(Texts(MatchMacros("hal_foo", Ptrs(add), types)),
              (std::vector<std::string>{"add_service(hal_foo, foo_service)"}));
}

TEST(MacrosTest, RDirFileNeedsDirectoryAndFile) {
    FakeTypes types;
    types.attrs["foo_data_file"] = {"file_type"};
    std::vector<Tuple> file_only = {T("foo_data_file", "file", {"read", "open"})};
    EXPECT_TRUE(MatchMacros("hal_foo", Ptrs(file_only), types).empty());
    std::vector<Tuple> both = {T("foo_data_file", "file", {"read", "open"}),
                               T("foo_data_file", "dir", {"search"})};
    EXPECT_EQ(Texts(MatchMacros("hal_foo", Ptrs(both), types)),
              (std::vector<std::string>{"r_dir_file(hal_foo, foo_data_file)"}));
}

TEST(MacrosTest, UncoveredPermissionsStayWithTheCaller) {
    FakeTypes types;
    types.attrs["vendor_foo_prop"] = {"property_type"};
    std::vector<Tuple> tuples = {T("vendor_foo_prop", "file", {"read", "write"})};
    auto uses = MatchMacros("hal_foo", Ptrs(tuples), types);
    ASSERT_EQ(uses.size(), 1u);
    // "write" is not part of get_prop.
    EXPECT_EQ(uses[0].covered.begin()->second, (std::set<std::string>{"read"}));
}

TEST(MacrosTest, TableMatchesTheMacroFile) {
    // Every macro in the table is one te_macros defines; the arguments are
    // numbered from 1 and the first is the domain.
    for (const MacroDef& macro : MacroTable()) {
        EXPECT_GE(macro.args, 1) << macro.name;
        EXPECT_LE(macro.args, 3) << macro.name;
        ASSERT_FALSE(macro.rules.empty()) << macro.name;
        EXPECT_EQ(macro.rules[0].src, "$1") << macro.name;
    }
}

}  // namespace selogger
