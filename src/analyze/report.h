/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "analyze/rulegen.h"
#include "label/plan.h"
#include "tuple.h"

namespace selogger {

struct ReportInput {
    // The collected denials, as they were.
    const std::vector<Tuple>& collected;
    const LabelPlan& labels;
    const RuleSet& rules;
    // Denials the kernel dropped, if the daemon knows.
    uint64_t kernel_lost = 0;
};

// The files to write, by relative path: "vendor/<domain>.te",
// "vendor/file_contexts", ..., "platform/...", and "REVIEW.md".
std::map<std::string, std::string> BuildOutputFiles(const ReportInput& input);

// One line per collected tuple, for looking at the raw data.
std::string FormatTuples(const std::vector<Tuple>& tuples);

}  // namespace selogger
