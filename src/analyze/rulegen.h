/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string>
#include <vector>

#include "analyze/macros.h"
#include "analyze/policy_db.h"
#include "tuple.h"

namespace selogger {

enum class RuleHome {
    kVendor,    // vendor sepolicy: the domain is the device's or a public one
    kPlatform,  // the domain is private to the platform; vendor policy cannot name it
};

// The rules for one source domain.
struct DomainRules {
    std::string domain;
    RuleHome home = RuleHome::kVendor;
    std::vector<std::string> macros;
    std::vector<std::string> allows;
    std::vector<std::string> xperms;
    // Rules that must not be added as they are, written as comments.
    std::vector<std::string> withheld;
};

// Something a person has to look at before using the rules.
struct ReviewNote {
    std::string domain;
    std::string text;
};

struct RuleSet {
    std::vector<DomainRules> domains;  // sorted by name
    std::vector<ReviewNote> notes;
};

// Turns the tuples into rules, using te_macros macros where they fit.
// policy may be null, in which case only the checks that need none are done.
RuleSet GenerateRules(const std::vector<Tuple>& tuples, const TypeInfo& types,
                      const PolicyDb* policy);

// "allow a b:file { open read };"
std::string FormatAllow(const std::string& source, const std::string& target,
                        const std::string& tclass, const std::set<std::string>& perms);

}  // namespace selogger
