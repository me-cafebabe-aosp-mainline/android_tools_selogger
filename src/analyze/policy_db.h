/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace selogger {

// Who owns a CIL file: decides which types count as platform or vendor.
enum class PolicyOrigin { kPlatform, kVendor };

struct GenfsEntry {
    std::string fs;    // "sysfs"
    std::string path;  // prefix inside the file system
    std::string type;
};

// What the analysis needs to know about the device's policy, read from the
// CIL files it ships: which attributes a type has, who defined it, and the
// genfscon labels.
//
// Platform types that vendor code may use appear in the vendor CIL under a
// versioned name ("foo_202604"). That is how public types are told from
// private ones.
class PolicyDb {
  public:
    // A node of a CIL expression: a name, or a list of nodes.
    struct Expr {
        std::string atom;
        std::vector<Expr> list;
        bool is_list = false;
    };

    // platform_version is the suffix of versioned names, e.g. "202604"; it may
    // be empty if the device does not have one.
    explicit PolicyDb(std::string platform_version = "")
        : platform_version_(std::move(platform_version)) {}

    void AddCil(std::string_view text, PolicyOrigin origin);

    bool HasType(const std::string& type) const { return type_origin_.contains(type); }
    bool HasAttribute(const std::string& type, const std::string& attribute) const;
    std::optional<PolicyOrigin> OriginOf(const std::string& type) const;
    // A platform type that vendor policy can refer to. False for vendor types
    // and for platform types that are private.
    bool IsPublic(const std::string& type) const { return public_types_.contains(type); }
    bool HasPublicTypes() const { return !public_types_.empty(); }

    // Longest genfscon prefix of path in file system fs.
    std::optional<GenfsEntry> LookupGenfs(const std::string& fs, const std::string& path) const;

    // Names of all types that have the attribute.
    std::set<std::string> MembersOf(const std::string& attribute) const;

  private:
    std::set<std::string> Evaluate(const Expr& expr, int depth) const;
    const std::set<std::string>& Members(const std::string& attribute, int depth) const;
    std::string StripVersion(const std::string& name, bool* versioned) const;

    std::string platform_version_;
    std::unordered_map<std::string, PolicyOrigin> type_origin_;
    std::set<std::string> attributes_;
    std::set<std::string> public_types_;
    // Attribute definitions, evaluated on first use.
    std::unordered_map<std::string, std::vector<Expr>> definitions_;
    mutable std::unordered_map<std::string, std::set<std::string>> members_;
    std::vector<GenfsEntry> genfs_;
};

}  // namespace selogger
