/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

#include "analyze/policy_db.h"
#include "analyze/rulegen.h"
#include "label/device_info.h"
#include "tuple.h"

namespace selogger {

// What the labelers propose. File names are "<home>/<name>" where home is
// "vendor" or "platform", e.g. "vendor/file_contexts".
struct LabelPlan {
    // Lines to add to the files, without duplicates, in the order added.
    std::map<std::string, std::vector<std::string>> files;
    // Lines for the .te file of a domain, e.g. macros that set it up.
    std::map<std::string, std::vector<std::string>> domain_lines;
    // The attributes of the types the plan declares, so that macros can be
    // matched against them.
    std::map<std::string, std::set<std::string>> new_types;
    // The denials that now have a proper target, and the tuples that stand
    // in for them.
    std::set<TupleKey> replaced;
    std::vector<Tuple> synthesized;
    std::vector<ReviewNote> notes;

    void AddLine(const std::string& file, const std::string& line);
    void AddDomainLine(const std::string& domain, const std::string& line);
};

// What the labelers share.
struct LabelContext {
    const DeviceInfo& device;
    const PolicyDb* policy;  // may be null
    LabelPlan* plan;

    bool TypeExists(const std::string& type) const;
    // A type name that neither the policy nor the plan uses; base, or base
    // with a number.
    std::string FreshTypeName(const std::string& base) const;
    // Whether the domain belongs to the platform's private policy.
    bool IsPlatformDomain(const std::string& domain) const;
    void Note(const std::string& domain, const std::string& text) const {
        plan->notes.push_back({domain, text});
    }
};

// A copy of the tuple aimed at a new target type.
Tuple Retarget(const Tuple& tuple, const std::string& ttype);

// Object classes whose instances have a path.
bool IsFileClass(const std::string& tclass);

// Types that do not say what an object is: a label on a path or property
// that is only a fallback, so a more specific label is worth proposing.
bool IsGenericFileType(const std::string& type);
bool IsGenericPropertyType(const std::string& type);
bool IsGenericServiceType(const std::string& type);

// "foo.bar-Baz" -> "foo_bar_baz"
std::string SanitizeName(const std::string& text);

// "a.b" -> "a\.b": the path as a file_contexts regular expression.
std::string EscapeRegex(const std::string& path);

// Directories that have at least min_children of the paths directly below
// them are returned instead of those paths.
std::vector<std::string> CollapseSiblings(const std::vector<std::string>& paths,
                                          size_t min_children);

}  // namespace selogger
