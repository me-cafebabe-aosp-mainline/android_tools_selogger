/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "label/plan.h"

#include <algorithm>
#include <cctype>

namespace selogger {

void LabelPlan::AddLine(const std::string& file, const std::string& line) {
    auto& lines = files[file];
    if (std::find(lines.begin(), lines.end(), line) == lines.end()) lines.push_back(line);
}

void LabelPlan::AddDomainLine(const std::string& domain, const std::string& line) {
    auto& lines = domain_lines[domain];
    if (std::find(lines.begin(), lines.end(), line) == lines.end()) lines.push_back(line);
}

bool LabelContext::TypeExists(const std::string& type) const {
    return (policy && policy->HasType(type)) || plan->new_types.contains(type);
}

std::string LabelContext::FreshTypeName(const std::string& base) const {
    if (!TypeExists(base)) return base;
    for (int i = 2;; i++) {
        std::string candidate = base + "_" + std::to_string(i);
        if (!TypeExists(candidate)) return candidate;
    }
}

bool LabelContext::IsPlatformDomain(const std::string& domain) const {
    return policy && policy->OriginOf(domain) == PolicyOrigin::kPlatform &&
           policy->HasPublicTypes() && !policy->IsPublic(domain);
}

Tuple Retarget(const Tuple& tuple, const std::string& ttype) {
    Tuple t = tuple;
    t.key.ttype = ttype;
    t.hints.clear();
    t.dirty_structure = t.dirty_count = false;
    return t;
}

bool IsFileClass(const std::string& tclass) {
    static const std::set<std::string> kClasses = {"file",     "dir",       "lnk_file", "chr_file",
                                                   "blk_file", "sock_file", "fifo_file"};
    return kClasses.contains(tclass);
}

bool IsGenericFileType(const std::string& type) {
    static const std::set<std::string> kGeneric = {"unlabeled",
                                                   "device",
                                                   "sysfs",
                                                   "proc",
                                                   "debugfs",
                                                   "tracefs",
                                                   "configfs",
                                                   "rootfs",
                                                   "tmpfs",
                                                   "labeledfs",
                                                   "vendor_file",
                                                   "system_file",
                                                   "vendor_data_file",
                                                   "system_data_file",
                                                   "system_data_root_file",
                                                   "vendor_configs_file",
                                                   "cache_file",
                                                   "mnt_vendor_file",
                                                   "vendor_userdir_file",
                                                   "sdcardfs",
                                                   "pstorefs",
                                                   "fuse",
                                                   "vfat",
                                                   "oemfs",
                                                   "firmware_file",
                                                   "metadata_file",
                                                   "efs_file",
                                                   "socket_device",
                                                   "system_ndebug_socket"};
    return kGeneric.contains(type);
}

bool IsGenericPropertyType(const std::string& type) {
    static const std::set<std::string> kGeneric = {"default_prop", "vendor_default_prop",
                                                   "unlabeled", "exported_default_prop"};
    return kGeneric.contains(type);
}

bool IsGenericServiceType(const std::string& type) {
    static const std::set<std::string> kGeneric = {"default_android_service",
                                                   "default_android_vndservice",
                                                   "default_android_hwservice", "unlabeled"};
    return kGeneric.contains(type);
}

std::string SanitizeName(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        } else if (!out.empty() && out.back() != '_') {
            out += '_';
        }
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty() || std::isdigit(static_cast<unsigned char>(out[0]))) out = "x" + out;
    return out;
}

std::string EscapeRegex(const std::string& path) {
    static const std::string kSpecial = ".+*?()[]{}|^$\\";
    std::string out;
    for (char c : path) {
        if (kSpecial.find(c) != std::string::npos) out += '\\';
        out += c;
    }
    return out;
}

std::vector<std::string> CollapseSiblings(const std::vector<std::string>& paths,
                                          size_t min_children) {
    std::map<std::string, std::vector<std::string>> by_parent;
    for (const std::string& path : paths) {
        size_t slash = path.rfind('/');
        by_parent[slash == std::string::npos || slash == 0 ? "/" : path.substr(0, slash)].push_back(
                path);
    }
    std::vector<std::string> out;
    for (auto& [parent, children] : by_parent) {
        if (parent != "/" && children.size() >= min_children) {
            out.push_back(parent);
        } else {
            out.insert(out.end(), children.begin(), children.end());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace selogger
