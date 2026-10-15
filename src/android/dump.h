/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string>
#include <vector>

namespace selogger {

// "selogger dump": turns the collected denials into sepolicy files.
int RunDump(const std::vector<std::string>& args);

}  // namespace selogger
