/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "analyze/rulegen.h"

#include <android-base/parseint.h>
#include <android-base/strings.h>

#include <algorithm>
#include <map>

namespace selogger {

namespace {

// Grants that are rarely right: a denial for one of these is a reason to
// ask why the access is needed, not to allow it.
struct RiskyPerm {
    const char* tclass;
    const char* perm;
    const char* why;
};
const RiskyPerm kRiskyPerms[] = {
        {"capability", "sys_admin", "CAP_SYS_ADMIN is close to root"},
        {"capability", "sys_module", "loading kernel modules"},
        {"capability", "sys_rawio", "raw I/O access"},
        {"capability", "sys_ptrace", "tracing other processes"},
        {"capability", "sys_boot", "rebooting the device"},
        {"capability2", "mac_admin", "changing SELinux labels"},
        {"process", "ptrace", "tracing other processes"},
        {"process", "execmem", "writable and executable memory"},
        {"process", "execmod", "executing modified file pages"},
        {"process", "setcurrent", "changing the SELinux context of a process"},
        {"security", "load_policy", "loading SELinux policy"},
        {"security", "setenforce", "switching SELinux mode"},
};

std::string Target(const Tuple& tuple) {
    return tuple.key.ttype == tuple.key.stype ? "self" : tuple.key.ttype;
}

uint64_t IoctlValue(const std::string& cmd) {
    uint64_t value = 0;
    android::base::ParseUint(cmd, &value);
    return value;
}

std::string FormatXperm(const Tuple& tuple) {
    std::vector<std::string> cmds(tuple.ioctls.begin(), tuple.ioctls.end());
    std::sort(cmds.begin(), cmds.end(), [](const std::string& a, const std::string& b) {
        return IoctlValue(a) < IoctlValue(b);
    });
    return "allowxperm " + tuple.key.stype + " " + Target(tuple) + ":" + tuple.key.tclass +
           " ioctl { " + android::base::Join(cmds, " ") + " };";
}

class Generator {
  public:
    Generator(const TypeInfo& types, const PolicyDb* policy) : types_(types), policy_(policy) {}

    void AddDomain(const std::string& domain, const std::vector<const Tuple*>& tuples,
                   RuleSet* out) {
        DomainRules rules;
        rules.domain = domain;
        rules.home = HomeOf(domain, out);

        std::vector<const Tuple*> usable;
        for (const Tuple* tuple : tuples) {
            if (Withhold(*tuple, out, &rules)) continue;
            usable.push_back(tuple);
        }

        CoveredPerms covered;
        for (MacroUse& use : MatchMacros(domain, usable, types_)) {
            for (const auto& [key, perms] : use.covered)
                covered[key].insert(perms.begin(), perms.end());
            rules.macros.push_back(std::move(use.text));
        }

        for (const Tuple* tuple : usable) {
            std::set<std::string> perms = tuple->perms;
            auto cov = covered.find(tuple->key);
            if (cov != covered.end()) {
                for (const std::string& perm : cov->second) perms.erase(perm);
            }
            if (perms.empty()) continue;
            rules.allows.push_back(FormatAllow(domain, Target(*tuple), tuple->key.tclass, perms));
            if (perms.contains("ioctl") && !tuple->ioctls.empty()) {
                rules.xperms.push_back(FormatXperm(*tuple));
            } else if (perms.contains("ioctl") && tuple->key.tclass != "netlink_audit_socket") {
                out->notes.push_back({domain, "ioctl on " + tuple->key.ttype + ":" +
                                                      tuple->key.tclass +
                                                      " was denied without a command number; "
                                                      "the allow rule alone does not grant it"});
            }
        }
        std::sort(rules.allows.begin(), rules.allows.end());
        std::sort(rules.xperms.begin(), rules.xperms.end());
        out->domains.push_back(std::move(rules));
    }

  private:
    RuleHome HomeOf(const std::string& domain, RuleSet* out) {
        if (!policy_) return RuleHome::kVendor;
        auto origin = policy_->OriginOf(domain);
        if (origin == PolicyOrigin::kPlatform && policy_->HasPublicTypes() &&
            !policy_->IsPublic(domain)) {
            out->notes.push_back({domain,
                                  "is a private platform domain, so its rules belong in the "
                                  "platform sepolicy; the vendor policy cannot name it"});
            return RuleHome::kPlatform;
        }
        return RuleHome::kVendor;
    }

    // Returns true if the tuple must not become an allow rule; the reason
    // goes to the notes and a commented rule to the output.
    bool Withhold(const Tuple& tuple, RuleSet* out, DomainRules* rules) {
        const std::string& domain = tuple.key.stype;
        auto withhold = [&](const std::string& why) {
            rules->withheld.push_back(
                    "# " + FormatAllow(domain, Target(tuple), tuple.key.tclass, tuple.perms));
            out->notes.push_back({domain, why});
            return true;
        };
        const std::string desc = tuple.key.ttype + ":" + tuple.key.tclass;

        if (tuple.key.ttype == "unlabeled") {
            return withhold("denial on " + desc +
                            ": the object has no label; label it instead of "
                            "allowing access to everything unlabeled");
        }
        if (policy_ && policy_->HasPublicTypes() && rules->home == RuleHome::kVendor &&
            policy_->OriginOf(tuple.key.ttype) == PolicyOrigin::kPlatform &&
            !policy_->IsPublic(tuple.key.ttype) && tuple.key.ttype != domain) {
            return withhold("target " + desc +
                            " is a private platform type; vendor policy cannot refer to "
                            "it (Treble). Use an attribute, a public type, or change the design");
        }
        for (const RiskyPerm& risky : kRiskyPerms) {
            if (tuple.key.tclass == risky.tclass && tuple.perms.contains(risky.perm)) {
                out->notes.push_back({domain, std::string("allows ") + risky.tclass + " " +
                                                      risky.perm + " (" + risky.why +
                                                      "); check that it is needed"});
            }
        }
        if (types_.HasAttribute(domain, "appdomain")) {
            out->notes.push_back({domain,
                                  "is an app domain: a denial here is usually an app bug, not a "
                                  "missing rule"});
        }
        if (tuple.key.tclass == "file" && tuple.perms.contains("execute") &&
            types_.HasAttribute(tuple.key.ttype, "data_file_type")) {
            out->notes.push_back({domain, "executes " + tuple.key.ttype +
                                                  " (a data type); executing "
                                                  "from data is mostly neverallowed"});
        }
        return false;
    }

    const TypeInfo& types_;
    const PolicyDb* policy_;
};

}  // namespace

std::string FormatAllow(const std::string& source, const std::string& target,
                        const std::string& tclass, const std::set<std::string>& perms) {
    std::string list = android::base::Join(perms, " ");
    return "allow " + source + " " + target + ":" + tclass + " " +
           (perms.size() == 1 ? list : "{ " + list + " }") + ";";
}

RuleSet GenerateRules(const std::vector<Tuple>& tuples, const TypeInfo& types,
                      const PolicyDb* policy) {
    std::map<std::string, std::vector<const Tuple*>> by_domain;
    for (const Tuple& tuple : tuples) by_domain[tuple.key.stype].push_back(&tuple);

    RuleSet out;
    Generator generator(types, policy);
    for (auto& [domain, domain_tuples] : by_domain) {
        std::sort(domain_tuples.begin(), domain_tuples.end(),
                  [](const Tuple* a, const Tuple* b) { return a->key < b->key; });
        generator.AddDomain(domain, domain_tuples, &out);
    }
    return out;
}

}  // namespace selogger
