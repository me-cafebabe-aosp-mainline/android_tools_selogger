/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <vector>

#include "label/plan.h"

namespace selogger {

struct LabelResult {
    LabelPlan plan;
    // The denials to generate rules from: the collected ones, where a
    // labeler proposed a label replaced by the same denial aimed at the new
    // type (or domain).
    std::vector<Tuple> tuples;
};

// Runs all labelers. policy may be null.
LabelResult RunLabelers(const std::vector<Tuple>& tuples, const DeviceInfo& device,
                        const PolicyDb* policy);

// The individual labelers. Each looks at tuples whose target (or, for
// daemons, source) is a generic fallback and records its proposals in
// ctx.plan, with the replaced and synthesized tuples.
void LabelInitDaemons(const std::vector<Tuple>& tuples, const LabelContext& ctx);
void LabelProperties(const std::vector<Tuple>& tuples, const LabelContext& ctx);
void LabelServices(const std::vector<Tuple>& tuples, const LabelContext& ctx);
void LabelFiles(const std::vector<Tuple>& tuples, const LabelContext& ctx);

}  // namespace selogger
