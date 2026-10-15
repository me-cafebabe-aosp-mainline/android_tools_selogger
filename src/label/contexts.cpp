/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "label/contexts.h"

#include <android-base/strings.h>

#include "avc.h"

namespace selogger {

namespace {

// Splits a non-comment line at whitespace.
std::vector<std::string> Fields(const std::string& line) {
    std::string trimmed = android::base::Trim(line);
    if (trimmed.empty() || trimmed[0] == '#') return {};
    return android::base::Tokenize(trimmed, " \t");
}

}  // namespace

void ServiceContexts::Add(std::string_view text) {
    for (const std::string& line : android::base::Split(std::string(text), "\n")) {
        std::vector<std::string> fields = Fields(line);
        if (fields.size() < 2) continue;
        types_.try_emplace(fields[0], TypeOfContext(fields[1]));
    }
}

std::string ServiceContexts::Lookup(const std::string& name) const {
    auto it = types_.find(name);
    return it == types_.end() ? "" : it->second;
}

void PropertyContexts::Add(std::string_view text) {
    for (const std::string& line : android::base::Split(std::string(text), "\n")) {
        std::vector<std::string> fields = Fields(line);
        if (fields.size() < 2) continue;
        bool exact = fields.size() > 2 && fields[2] == "exact";
        entries_.push_back({fields[0], TypeOfContext(fields[1]), exact});
    }
}

std::string PropertyContexts::Lookup(const std::string& name) const {
    const Entry* best = nullptr;
    for (const Entry& entry : entries_) {
        bool matches = entry.exact ? name == entry.name : name.starts_with(entry.name);
        if (!matches) continue;
        if (!best || entry.name.size() > best->name.size() ||
            (entry.name.size() == best->name.size() && entry.exact && !best->exact)) {
            best = &entry;
        }
    }
    return best ? best->type : "";
}

}  // namespace selogger
