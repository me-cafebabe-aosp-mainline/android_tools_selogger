/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace selogger {

// One parsed "avc: denied" audit message.
struct AvcDenial {
    std::vector<std::string> perms;
    std::string scontext;
    std::string tcontext;
    // Type field of the contexts, e.g. "hal_foo_default" for
    // "u:r:hal_foo_default:s0".
    std::string stype;
    std::string ttype;
    std::string tclass;
    bool permissive = false;
    // Every other key=value pair, with hex-encoded values decoded.
    std::map<std::string, std::string> fields;

    // Returns the value of a field, or an empty string.
    const std::string& Get(const std::string& key) const;
};

// Parses the string logd stores in the events buffer for tag "auditd", which
// is an audit message such as
//   type=1400 audit(0.0:12): avc:  denied  { read } for  comm="foo" ...
// Anything that is not a denial (granted, policy load, other audit types)
// yields nullopt.
std::optional<AvcDenial> ParseAvc(std::string_view message);

// Returns the type of a security context, or an empty string if it is not one.
std::string TypeOfContext(std::string_view context);

// Decodes the upper-case hex form the kernel uses for strings with spaces or
// control characters. Returns nullopt unless the input is such a string.
std::optional<std::string> DecodeAuditHex(std::string_view hex);

}  // namespace selogger
