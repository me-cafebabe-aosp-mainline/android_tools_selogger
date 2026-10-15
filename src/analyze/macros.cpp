/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "analyze/macros.h"

#include <algorithm>
#include <array>
#include <optional>

namespace selogger {

namespace {

using Set = std::set<std::string>;

// The permission sets of public/global_macros.
const Set kRFile = {"getattr", "open", "read", "ioctl", "lock", "map", "watch", "watch_reads"};
const Set kWFile = {"open", "append", "write", "lock", "map"};
const Set kRxFile = {"getattr", "open",  "read",        "ioctl",   "lock",
                     "map",     "watch", "watch_reads", "execute", "execute_no_trans"};
const Set kRDir = {"open", "getattr", "read", "search", "ioctl", "lock", "watch", "watch_reads"};

// Arguments are "$1".."$3"; index 0 is unused.
using Binding = std::array<std::string, 4>;

struct ParsedTarget {
    int arg = 0;       // 0 for a literal
    std::string text;  // the literal, or the suffix after the argument
};

ParsedTarget ParseTarget(const std::string& tgt) {
    if (tgt.size() >= 2 && tgt[0] == '$') return {tgt[1] - '0', tgt.substr(2)};
    return {0, tgt};
}

bool Bind(Binding& binding, int arg, const std::string& value) {
    if (binding[arg].empty()) {
        binding[arg] = value;
        return true;
    }
    return binding[arg] == value;
}

// Matches a rule against a tuple of the domain, extending the binding.
bool MatchRule(const RuleTemplate& rule, const std::string& domain, const Tuple& tuple,
               Binding* binding) {
    if (!rule.classes.contains(tuple.key.tclass)) return false;
    bool shares_perm = std::any_of(tuple.perms.begin(), tuple.perms.end(),
                                   [&](const std::string& p) { return rule.perms.contains(p); });
    if (!shares_perm) return false;
    for (const std::string& perm : rule.required) {
        if (!tuple.perms.contains(perm)) return false;
    }

    Binding b = *binding;
    ParsedTarget src = ParseTarget(rule.src);
    if (src.arg != 1 || !Bind(b, 1, domain)) return false;

    ParsedTarget tgt = ParseTarget(rule.tgt);
    const std::string& ttype = tuple.key.ttype;
    if (tgt.arg == 0) {
        if (ttype != tgt.text) return false;
    } else {
        if (ttype.size() <= tgt.text.size() || !ttype.ends_with(tgt.text)) return false;
        if (!Bind(b, tgt.arg, ttype.substr(0, ttype.size() - tgt.text.size()))) return false;
    }
    *binding = b;
    return true;
}

bool ConstraintsHold(const MacroDef& macro, const Binding& binding, const TypeInfo& types) {
    for (const ArgConstraint& c : macro.constraints) {
        const std::string& type = binding[c.arg];
        if (!type.empty() && !types.HasAttribute(type, c.attribute)) return false;
    }
    return true;
}

std::string Render(const MacroDef& macro, const Binding& binding) {
    std::string out = macro.name + "(";
    for (int i = 1; i <= macro.args; i++) out += (i > 1 ? ", " : "") + binding[i];
    return out + ")";
}

struct Candidate {
    const MacroDef* macro;
    Binding binding;
    CoveredPerms covered;
    size_t covered_count = 0;
};

// All bindings of the macro's arguments that the domain's denials support.
std::vector<Binding> FindBindings(const MacroDef& macro, const std::string& domain,
                                  const std::vector<const Tuple*>& tuples, const TypeInfo& types) {
    std::set<Binding> frontier;
    Binding empty;
    empty[1] = domain;
    frontier.insert(empty);

    // Each rule can bind arguments the earlier ones left open.
    for (const RuleTemplate& rule : macro.rules) {
        if (ParseTarget(rule.src).arg != 1) continue;
        std::set<Binding> next;
        for (const Binding& base : frontier) {
            bool extended = false;
            for (const Tuple* tuple : tuples) {
                Binding b = base;
                if (MatchRule(rule, domain, *tuple, &b) && ConstraintsHold(macro, b, types)) {
                    next.insert(b);
                    extended = true;
                }
            }
            if (!extended) next.insert(base);
        }
        frontier = std::move(next);
    }

    std::vector<Binding> complete;
    for (const Binding& b : frontier) {
        bool all_bound = true;
        for (int i = 1; i <= macro.args; i++) all_bound &= !b[i].empty();
        if (all_bound) complete.push_back(b);
    }
    return complete;
}

std::optional<Candidate> Evaluate(const MacroDef& macro, const std::string& domain,
                                  const Binding& binding, const std::vector<const Tuple*>& tuples) {
    Candidate candidate{&macro, binding, {}, 0};
    int seen = 0;
    bool anchor_seen = macro.anchor < 0;
    for (size_t i = 0; i < macro.rules.size(); i++) {
        const RuleTemplate& rule = macro.rules[i];
        if (ParseTarget(rule.src).arg != 1) continue;
        bool rule_seen = false;
        for (const Tuple* tuple : tuples) {
            Binding b = binding;
            if (!MatchRule(rule, domain, *tuple, &b) || b != binding) continue;
            rule_seen = true;
            for (const std::string& perm : tuple->perms) {
                if (rule.perms.contains(perm)) candidate.covered[tuple->key].insert(perm);
            }
        }
        if (rule_seen) seen++;
        if (rule_seen && static_cast<int>(i) == macro.anchor) anchor_seen = true;
    }
    if (seen < macro.min_seen || !anchor_seen) return std::nullopt;
    for (const auto& [key, perms] : candidate.covered) candidate.covered_count += perms.size();
    return candidate;
}

}  // namespace

const std::vector<MacroDef>& MacroTable() {
    static const std::vector<MacroDef> kTable = {
            {"get_prop",
             2,
             {{"$1", "$2", {"file"}, {"getattr", "open", "read", "map"}, {}}},
             {{2, "property_type"}}},
            {"set_prop",
             2,
             {{"$1", "property_socket", {"sock_file"}, {"write"}, {}},
              {"$1", "init", {"unix_stream_socket"}, {"connectto"}, {}},
              {"$1", "$2", {"property_service"}, {"set"}, {"set"}},
              {"$1", "$2", {"file"}, {"getattr", "open", "read", "map"}, {}}},
             {{2, "property_type"}},
             1,
             2},
            {"unix_socket_connect",
             3,
             {{"$1", "$2_socket", {"sock_file"}, {"write"}, {}},
              {"$1", "$3", {"unix_stream_socket"}, {"connectto"}, {}}},
             {{3, "domain"}},
             2},
            {"unix_socket_send",
             3,
             {{"$1", "$2_socket", {"sock_file"}, {"write"}, {}},
              {"$1", "$3", {"unix_dgram_socket"}, {"sendto"}, {}}},
             {{3, "domain"}},
             2},
            {"binder_use", 1, {{"$1", "servicemanager", {"binder"}, {"call", "transfer"}, {}}}, {}},
            {"hwbinder_use",
             1,
             {{"$1", "hwservicemanager", {"binder"}, {"call", "transfer"}, {}}},
             {}},
            {"vndbinder_use",
             1,
             {{"$1", "vndbinder_device", {"chr_file"}, kRFile, {}},
              {"$1", "vndservicemanager", {"binder"}, {"call", "transfer"}, {}}},
             {},
             1,
             1},
            {"binder_call",
             2,
             {{"$1", "$2", {"binder"}, {"call", "transfer"}, {}},
              {"$1", "$2", {"fd"}, {"use"}, {}}},
             {{2, "domain"}},
             1,
             0},
            {"read_logd",
             1,
             {{"$1", "logcat_exec", {"file"}, kRxFile, {}},
              {"$1", "logdr_socket", {"sock_file"}, {"write"}, {}},
              {"$1", "logd", {"unix_stream_socket"}, {"connectto"}, {}}},
             {},
             1,
             2},
            {"write_logd",
             1,
             {{"$1", "logdw_socket", {"sock_file"}, {"write"}, {}},
              {"$1", "logd", {"unix_dgram_socket"}, {"sendto"}, {}},
              {"$1", "pmsg_device", {"chr_file"}, kWFile, {}}},
             {},
             1,
             1},
            {"control_logd",
             1,
             {{"$1", "logd_socket", {"sock_file"}, {"write"}, {}},
              {"$1", "logd", {"unix_stream_socket"}, {"connectto"}, {}}},
             {},
             2},
            {"add_service",
             2,
             {{"$1", "$2", {"service_manager"}, {"add", "find"}, {"add"}}},
             {{2, "service_manager_type"}},
             1,
             0},
            {"add_hwservice",
             2,
             {{"$1", "$2", {"hwservice_manager"}, {"add", "find"}, {"add"}},
              {"$1", "hidl_base_hwservice", {"hwservice_manager"}, {"add"}, {}}},
             {{2, "hwservice_manager_type"}},
             1,
             0},
            {"r_dir_file",
             2,
             {{"$1", "$2", {"dir"}, kRDir, {}}, {"$1", "$2", {"file", "lnk_file"}, kRFile, {}}},
             {{2, "file_type"}},
             2},
            {"domain_auto_trans",
             3,
             {{"$1", "$2", {"file"}, {"getattr", "open", "read", "execute", "map"}, {}},
              {"$1", "$3", {"process"}, {"transition"}, {"transition"}},
              {"$1", "$3", {"process"}, {"siginh", "rlimitinh"}, {}}},
             {{2, "exec_type"}, {3, "domain"}},
             2,
             1},
    };
    return kTable;
}

std::vector<MacroUse> MatchMacros(const std::string& domain,
                                  const std::vector<const Tuple*>& tuples, const TypeInfo& types) {
    std::vector<Candidate> candidates;
    for (const MacroDef& macro : MacroTable()) {
        for (const Binding& binding : FindBindings(macro, domain, tuples, types)) {
            if (auto candidate = Evaluate(macro, domain, binding, tuples)) {
                candidates.push_back(std::move(*candidate));
            }
        }
    }

    // The macro that explains the most denials goes first; of equals, the
    // one with fewer arguments is the more specific idiom.
    std::stable_sort(candidates.begin(), candidates.end(),
                     [](const Candidate& a, const Candidate& b) {
                         if (a.covered_count != b.covered_count)
                             return a.covered_count > b.covered_count;
                         return a.macro->args < b.macro->args;
                     });

    CoveredPerms claimed;
    std::vector<MacroUse> uses;
    for (const Candidate& candidate : candidates) {
        bool adds_something = false;
        for (const auto& [key, perms] : candidate.covered) {
            for (const std::string& perm : perms) {
                adds_something |= !claimed[key].contains(perm);
            }
        }
        if (!adds_something) continue;
        MacroUse use{Render(*candidate.macro, candidate.binding), candidate.covered};
        for (const auto& [key, perms] : candidate.covered)
            claimed[key].insert(perms.begin(), perms.end());
        uses.push_back(std::move(use));
    }
    std::sort(uses.begin(), uses.end(),
              [](const MacroUse& a, const MacroUse& b) { return a.text < b.text; });
    return uses;
}

}  // namespace selogger
