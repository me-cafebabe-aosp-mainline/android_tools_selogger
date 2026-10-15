/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string>
#include <vector>

namespace selogger {

// The layout rules the device trees check with
// device/mainline/common/build/tools/check_sepolicy.py.

// Orders .te lines: rules before macro calls, then case-insensitively.
bool TeLineLess(const std::string& a, const std::string& b);

// Orders file_contexts regular expressions: directories before the files
// next to them, parents before children.
bool FileContextsLess(const std::string& a, const std::string& b);

// Writes a line of a *_contexts file the way the checker wants it (fields
// separated by tabs where it asks for it). `file` is the file name without
// directory, e.g. "file_contexts"; `line` has its fields separated by
// spaces, as the labelers write them.
std::string FormatContextsLine(const std::string& file, const std::string& line);

// Sorts the lines of a file in the order the checker expects for its kind:
// "*.te" files by TeLineLess, contexts files by their entries.
void SortLines(const std::string& file, std::vector<std::string>* lines);

}  // namespace selogger
