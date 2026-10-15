/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-base/strings.h>

#include <map>

#include "label/labeler.h"

namespace selogger {

namespace {

// Threads of init itself and of the kernel's helpers are not daemons.
bool IsInitInternal(const std::string& comm) {
    return comm == "init" || comm == "ueventd" || comm == "watchdogd" ||
           comm.starts_with("kworker") || comm.starts_with("kthread") ||
           comm.starts_with("ksoftirqd");
}

}  // namespace

// A service that init starts from a binary labeled vendor_file or
// system_file keeps init's own domain, and every denial it causes shows up
// as one of init's. The process name leads to the binary, and the binary
// to a domain of its own.
void LabelInitDaemons(const std::vector<Tuple>& tuples, const LabelContext& ctx) {
    std::map<std::string, std::string> domain_of_comm;
    std::set<std::string> reported;
    for (const Tuple& tuple : tuples) {
        if (tuple.key.stype != "init") continue;
        auto it = tuple.hints.find(kHintComm);
        if (it == tuple.hints.end() || it->second.size() != 1) continue;
        const std::string& comm = *it->second.begin();
        if (IsInitInternal(comm)) continue;

        auto known = domain_of_comm.find(comm);
        if (known == domain_of_comm.end()) {
            std::vector<std::string> executables = ctx.device.FindExecutables(comm);
            if (executables.size() != 1) {
                if (reported.insert(comm).second) {
                    ctx.Note("init",
                             "runs \"" + comm + "\" but " +
                                     (executables.empty() ? "no executable"
                                                          : std::to_string(executables.size()) +
                                                                    " executables") +
                                     " in the bin directories match; give the service a domain by "
                                     "hand");
                }
                continue;
            }
            const std::string& executable = executables[0];
            std::string domain = ctx.FreshTypeName(SanitizeName(comm));
            std::string exec = ctx.FreshTypeName(domain + "_exec");
            bool vendor = executable.starts_with("/vendor/") || executable.starts_with("/odm/");
            std::string home = vendor ? "vendor" : "platform";
            if (!vendor) {
                ctx.Note("init",
                         executable +
                                 " is not in the vendor partition; its domain belongs to the "
                                 "platform policy");
            }

            ctx.plan->new_types[domain] = {"domain"};
            ctx.plan->new_types[exec] = {"exec_type", "file_type"};
            ctx.plan->AddDomainLine(domain, "type " + domain + ", domain;");
            ctx.plan->AddDomainLine(domain,
                                    "type " + exec + ", exec_type, " +
                                            (vendor ? "vendor_file_type, " : "system_file_type, ") +
                                            "file_type;");
            ctx.plan->AddDomainLine(domain, "init_daemon_domain(" + domain + ")");
            ctx.plan->AddLine(home + "/file_contexts",
                              EscapeRegex(executable) + " u:object_r:" + exec + ":s0");
            known = domain_of_comm.emplace(comm, domain).first;
        }

        Tuple moved = tuple;
        moved.key.stype = known->second;
        moved.hints.erase(kHintComm);
        ctx.plan->synthesized.push_back(std::move(moved));
        ctx.plan->replaced.insert(tuple.key);
    }
}

}  // namespace selogger
