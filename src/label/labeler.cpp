/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "label/labeler.h"

#include <algorithm>

namespace selogger {

namespace {

// Applies what a labeler added to the plan since `replaced_before` and
// `synthesized_before` to the working set of tuples.
void Apply(const LabelPlan& plan, size_t synthesized_before,
           const std::set<TupleKey>& replaced_before, std::vector<Tuple>* working) {
    std::vector<Tuple> next;
    for (Tuple& tuple : *working) {
        bool newly_replaced =
                plan.replaced.contains(tuple.key) && !replaced_before.contains(tuple.key);
        if (!newly_replaced) next.push_back(std::move(tuple));
    }
    for (size_t i = synthesized_before; i < plan.synthesized.size(); i++) {
        // Merge into an existing tuple of the same key, if any.
        auto same = std::find_if(next.begin(), next.end(),
                                 [&](const Tuple& t) { return t.key == plan.synthesized[i].key; });
        if (same == next.end()) {
            next.push_back(plan.synthesized[i]);
        } else {
            same->perms.insert(plan.synthesized[i].perms.begin(), plan.synthesized[i].perms.end());
            same->ioctls.insert(plan.synthesized[i].ioctls.begin(),
                                plan.synthesized[i].ioctls.end());
            same->count += plan.synthesized[i].count;
        }
    }
    *working = std::move(next);
}

}  // namespace

LabelResult RunLabelers(const std::vector<Tuple>& tuples, const DeviceInfo& device,
                        const PolicyDb* policy) {
    LabelResult result;
    result.tuples = tuples;
    LabelContext ctx{device, policy, &result.plan};

    // Order matters: a daemon found in init's denials is a new domain, and
    // the labelers after it should see its denials as the domain's own.
    using Labeler = void (*)(const std::vector<Tuple>&, const LabelContext&);
    for (Labeler labeler : {LabelInitDaemons, LabelProperties, LabelServices, LabelFiles}) {
        size_t synthesized_before = result.plan.synthesized.size();
        std::set<TupleKey> replaced_before = result.plan.replaced;
        labeler(result.tuples, ctx);
        Apply(result.plan, synthesized_before, replaced_before, &result.tuples);
    }
    return result;
}

}  // namespace selogger
