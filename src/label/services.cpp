/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-base/strings.h>

#include <algorithm>

#include "label/labeler.h"

namespace selogger {

namespace {

// "android.hardware.light.ILights/default" -> "hal_light_ilights"
// "android.hardware.light@2.0::ILight" -> "hal_light_2_0_ilight"
std::string ServiceTypeBase(const std::string& name, const std::string& domain, bool* hal) {
    std::string rest = name;
    *hal = domain.starts_with("hal_");
    for (const char* prefix :
         {"android.hardware.", "android.frameworks.", "android.system.", "android."}) {
        if (rest.starts_with(prefix)) {
            if (std::string(prefix) == "android.hardware.") *hal = true;
            rest = rest.substr(std::string(prefix).size());
            break;
        }
    }
    // The instance ("/default") says which one, not what it is.
    std::string base = SanitizeName(rest.substr(0, rest.find('/')));
    return (*hal && !base.starts_with("hal_") ? "hal_" : "") + base;
}

// The HAL attribute (hal_foo of hal_foo_server) the domain belongs to.
std::string HalAttributeOf(const std::string& domain, const PolicyDb* policy) {
    if (!policy) return "";
    std::string candidate = domain;
    for (;;) {
        if (policy->HasAttribute(domain, candidate + "_server")) return candidate;
        size_t cut = candidate.rfind('_');
        if (cut == std::string::npos || cut < 4) return "";
        candidate.resize(cut);
    }
}

}  // namespace

void LabelServices(const std::vector<Tuple>& tuples, const LabelContext& ctx) {
    for (const Tuple& tuple : tuples) {
        ServiceKind kind;
        const char* hint_kind;
        if (tuple.key.tclass == "service_manager") {
            kind = tuple.key.ttype == "default_android_vndservice" ? ServiceKind::kVndService
                                                                   : ServiceKind::kService;
            hint_kind = kHintService;
        } else if (tuple.key.tclass == "hwservice_manager") {
            kind = ServiceKind::kHwService;
            hint_kind = kHintHwService;
        } else {
            continue;
        }
        if (!IsGenericServiceType(tuple.key.ttype)) continue;
        auto hint = tuple.hints.find(hint_kind);
        if (hint == tuple.hints.end()) continue;

        const std::string& domain = tuple.key.stype;
        std::string home = ctx.IsPlatformDomain(domain) ? "platform" : "vendor";
        const char* contexts = kind == ServiceKind::kHwService    ? "hwservice_contexts"
                               : kind == ServiceKind::kVndService ? "vndservice_contexts"
                                                                  : "service_contexts";
        const char* suffix = kind == ServiceKind::kHwService ? "_hwservice" : "_service";

        std::map<std::string, std::string> type_of_base;
        size_t labeled = 0;
        for (const std::string& name : hint->second) {
            std::string existing = ctx.device.ServiceLabel(kind, name);
            if (!existing.empty() && !IsGenericServiceType(existing)) {
                ctx.Note(domain, name + " is labeled " + existing + " in the " + contexts +
                                         " on the device but the denial shows " + tuple.key.ttype);
                continue;
            }

            bool hal = false;
            std::string base = ServiceTypeBase(name, domain, &hal) + suffix;
            auto known = type_of_base.find(base);
            std::string type;
            if (known != type_of_base.end()) {
                type = known->second;
            } else {
                type = ctx.FreshTypeName(base);
                type_of_base[base] = type;
                std::set<std::string> attrs;
                if (kind == ServiceKind::kService) attrs = {"service_manager_type"};
                if (kind == ServiceKind::kHwService) attrs = {"hwservice_manager_type"};
                if (kind == ServiceKind::kVndService) attrs = {"vndservice_manager_type"};
                if (hal && kind != ServiceKind::kVndService) attrs.insert("hal_service_type");
                ctx.plan->new_types[type] = attrs;
                ctx.plan->AddLine(home + "/service.te",
                                  "type " + type + ", " + android::base::Join(attrs, ", ") + ";");
            }
            ctx.plan->AddLine(home + "/" + contexts, name + " u:object_r:" + type + ":s0");
            labeled++;

            // A HAL server registers through the hal_foo attribute pair,
            // which also gives its clients access.
            std::string hal_attr = tuple.perms.contains("add") && kind != ServiceKind::kVndService
                                           ? HalAttributeOf(domain, ctx.policy)
                                           : "";
            if (hal_attr.empty()) {
                ctx.plan->synthesized.push_back(Retarget(tuple, type));
                continue;
            }
            ctx.plan->AddDomainLine(domain, std::string(kind == ServiceKind::kHwService
                                                                ? "hal_attribute_hwservice("
                                                                : "hal_attribute_service(") +
                                                    hal_attr + ", " + type + ")");
            Tuple rest = Retarget(tuple, type);
            rest.perms.erase("add");
            rest.perms.erase("find");
            if (!rest.perms.empty()) ctx.plan->synthesized.push_back(std::move(rest));
        }
        if (labeled == hint->second.size()) ctx.plan->replaced.insert(tuple.key);
    }
}

}  // namespace selogger
