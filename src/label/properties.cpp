/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include <android-base/strings.h>

#include "label/labeler.h"

namespace selogger {

namespace {

constexpr size_t kMaxListedProperties = 12;

bool IsVendorProperty(const std::string& name) {
    return name.starts_with("vendor.") || name.starts_with("ro.vendor.") ||
           name.starts_with("persist.vendor.");
}

// "ro.vendor.foo.bar" -> "vendor_foo_bar_prop"
std::string PropertyTypeBase(const std::string& name) {
    std::string rest = name;
    for (const char* prefix : {"ro.", "persist."}) {
        if (rest.starts_with(prefix)) {
            rest = rest.substr(std::string(prefix).size());
            break;
        }
    }
    if (rest.starts_with("vendor.")) rest = rest.substr(7);
    return "vendor_" + SanitizeName(rest) + "_prop";
}

}  // namespace

void LabelProperties(const std::vector<Tuple>& tuples, const LabelContext& ctx) {
    for (const Tuple& tuple : tuples) {
        if (!IsGenericPropertyType(tuple.key.ttype)) continue;
        const std::string& domain = tuple.key.stype;

        // Reading a property leaves no name in the denial, only the label of
        // the file that holds it.
        if (tuple.key.tclass == "file") {
            std::vector<std::string> names = ctx.device.PropertiesLabeled(tuple.key.ttype);
            if (names.empty()) continue;
            if (names.size() > kMaxListedProperties) {
                ctx.Note(domain, "reads a property labeled " + tuple.key.ttype +
                                         ", of which there are " + std::to_string(names.size()) +
                                         "; the denial does not say which. Find it in the source "
                                         "and label it");
            } else {
                ctx.Note(domain, "reads a property labeled " + tuple.key.ttype +
                                         "; one of: " + android::base::Join(names, ", ") +
                                         ". Give it its own label");
            }
            continue;
        }
        if (tuple.key.tclass != "property_service") continue;

        auto hint = tuple.hints.find(kHintProperty);
        if (hint == tuple.hints.end()) continue;

        size_t labeled = 0;
        for (const std::string& name : hint->second) {
            if (name.starts_with("ctl.")) {
                ctx.Note(domain,
                         "starts or stops a service through " + name +
                                 ", which is labeled in the platform's property_contexts per "
                                 "service; use the ctl_*_prop type of that service");
                continue;
            }
            std::string existing = ctx.device.PropertyLabel(name);
            if (!existing.empty() && !IsGenericPropertyType(existing)) {
                ctx.Note(domain, name + " is labeled " + existing +
                                         " in property_contexts but the denial shows " +
                                         tuple.key.ttype +
                                         "; the device may be running older policy");
                continue;
            }

            bool vendor = IsVendorProperty(name);
            if (!vendor) {
                ctx.Note(domain, name + " is outside the vendor property namespaces (vendor.*, "
                                        "ro.vendor.*, persist.vendor.*); its label belongs to the "
                                        "platform policy, or the property should be renamed");
            }
            std::string home = vendor ? "vendor" : "platform";
            std::string type = ctx.FreshTypeName(PropertyTypeBase(name));
            ctx.plan->new_types[type] = {
                    "property_type", vendor ? "vendor_property_type" : "system_property_type",
                    vendor ? "vendor_internal_property_type" : "system_internal_property_type"};
            ctx.plan->AddLine(
                    home + "/property.te",
                    (vendor ? "vendor_internal_prop(" : "system_internal_prop(") + type + ")");
            ctx.plan->AddLine(home + "/property_contexts",
                              name + " u:object_r:" + type + ":s0 exact");
            ctx.plan->synthesized.push_back(Retarget(tuple, type));
            labeled++;
        }
        if (labeled == hint->second.size()) ctx.plan->replaced.insert(tuple.key);
    }
}

}  // namespace selogger
