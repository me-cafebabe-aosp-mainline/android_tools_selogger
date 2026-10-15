/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace selogger {

// Parsers for the *_contexts files that name objects by string. They return
// the type of the context ("vendor_foo_prop" for "u:object_r:vendor_foo_prop:s0").

// service_contexts, hwservice_contexts, vndservice_contexts: "name context",
// matched exactly. Later files do not override earlier ones.
class ServiceContexts {
  public:
    void Add(std::string_view text);
    std::string Lookup(const std::string& name) const;

  private:
    std::map<std::string, std::string> types_;
};

// property_contexts: "name context [exact] [value type]". A name without
// "exact" matches every property that starts with it; the longest name wins,
// and an exact entry beats a prefix of the same length.
class PropertyContexts {
  public:
    void Add(std::string_view text);
    std::string Lookup(const std::string& name) const;

  private:
    struct Entry {
        std::string name;
        std::string type;
        bool exact;
    };
    std::vector<Entry> entries_;
};

}  // namespace selogger
