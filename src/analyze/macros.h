/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <map>
#include <set>
#include <string>
#include <vector>

#include "tuple.h"

namespace selogger {

// Attribute lookups for the types in a policy, and the types the labelers
// propose, which are not in any policy yet. A type nothing is known about
// has no attributes.
class TypeInfo {
  public:
    virtual ~TypeInfo() = default;
    virtual bool HasAttribute(const std::string& type, const std::string& attribute) const = 0;
};

// One allow rule of a te_macros macro. src and tgt are a literal type, "$N"
// for a macro argument, or "$N<suffix>" for an argument with a fixed suffix
// ("$2_socket").
struct RuleTemplate {
    std::string src;
    std::string tgt;
    std::set<std::string> classes;
    std::set<std::string> perms;
    // Permissions that have to be among the denied ones for the rule to count
    // as seen, when sharing just one of the perms would be a stretch.
    std::set<std::string> required;
};

struct ArgConstraint {
    int arg;
    std::string attribute;
};

// A macro from system/sepolicy/public/te_macros. Only rules whose source is
// the first argument (the domain) can be seen in a denial of that domain; the
// others are granted as a side effect.
struct MacroDef {
    std::string name;
    int args;
    std::vector<RuleTemplate> rules;
    std::vector<ArgConstraint> constraints;
    // How many of the rules have to be seen, and which one has to be.
    int min_seen = 1;
    int anchor = -1;
    // The macro grants something vendor domains are neverallowed (read_logd()
    // lets the domain run logcat), so it is only used for platform domains.
    bool platform_only = false;
};

const std::vector<MacroDef>& MacroTable();

// A denied permission set of a tuple that a macro makes unnecessary to
// write out.
using CoveredPerms = std::map<TupleKey, std::set<std::string>>;

struct MacroUse {
    std::string text;  // "get_prop(hal_foo, vendor_foo_prop)"
    CoveredPerms covered;
};

// Finds the macros that stand in for denials of one source domain. The uses
// are disjoint: every denied (tuple, permission) is covered by at most one.
std::vector<MacroUse> MatchMacros(const std::string& domain,
                                  const std::vector<const Tuple*>& tuples, const TypeInfo& types,
                                  bool vendor_domain = true);

}  // namespace selogger
