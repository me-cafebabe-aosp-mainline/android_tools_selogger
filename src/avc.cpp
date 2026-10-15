/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "avc.h"

#include <android-base/strings.h>

#include <cctype>

namespace selogger {

namespace {

const std::string kEmpty;

int HexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

// Service manager names are plain text that can look like hex ("cafe").
bool IsServiceManagerClass(const std::string& tclass) {
    return tclass == "service_manager" || tclass == "hwservice_manager";
}

struct Token {
    std::string key;
    std::string value;
    bool quoted = false;
};

// Splits "k=v k2="quoted v" word" into tokens, skipping bare words.
std::vector<Token> Tokenize(std::string_view text) {
    std::vector<Token> tokens;
    size_t i = 0;
    while (i < text.size()) {
        while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) i++;
        size_t start = i;
        while (i < text.size() && !std::isspace(static_cast<unsigned char>(text[i])) &&
               text[i] != '=') {
            i++;
        }
        if (i >= text.size() || text[i] != '=') continue;  // bare word

        Token token;
        token.key = std::string(text.substr(start, i - start));
        i++;  // '='
        if (i < text.size() && text[i] == '"') {
            size_t end = text.find('"', i + 1);
            if (end == std::string_view::npos) end = text.size();
            token.value = std::string(text.substr(i + 1, end - i - 1));
            token.quoted = true;
            i = end < text.size() ? end + 1 : end;
        } else {
            size_t end = i;
            while (end < text.size() && !std::isspace(static_cast<unsigned char>(text[end]))) end++;
            token.value = std::string(text.substr(i, end - i));
            i = end;
        }
        tokens.push_back(std::move(token));
    }
    return tokens;
}

}  // namespace

const std::string& AvcDenial::Get(const std::string& key) const {
    auto it = fields.find(key);
    return it == fields.end() ? kEmpty : it->second;
}

std::string TypeOfContext(std::string_view context) {
    // user:role:type:sensitivity[:categories]
    std::vector<std::string> parts = android::base::Split(std::string(context), ":");
    if (parts.size() < 4 || parts[2].empty()) return "";
    return parts[2];
}

std::optional<std::string> DecodeAuditHex(std::string_view hex) {
    if (hex.size() < 2 || hex.size() % 2 != 0) return std::nullopt;
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = HexValue(hex[i]);
        int lo = HexValue(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        char c = static_cast<char>(hi * 16 + lo);
        if (!std::isprint(static_cast<unsigned char>(c))) return std::nullopt;
        out.push_back(c);
    }
    return out;
}

std::optional<AvcDenial> ParseAvc(std::string_view message) {
    size_t avc = message.find("avc:");
    if (avc == std::string_view::npos) return std::nullopt;

    std::string_view rest = message.substr(avc + 4);
    size_t open = rest.find('{');
    size_t close = rest.find('}');
    if (open == std::string_view::npos || close == std::string_view::npos || close < open) {
        return std::nullopt;
    }
    if (android::base::Trim(std::string(rest.substr(0, open))) != "denied") return std::nullopt;

    AvcDenial denial;
    denial.perms =
            android::base::Tokenize(std::string(rest.substr(open + 1, close - open - 1)), " \t");
    if (denial.perms.empty()) return std::nullopt;

    std::vector<Token> tokens = Tokenize(rest.substr(close + 1));
    for (const Token& token : tokens) {
        if (token.key == "scontext") {
            denial.scontext = token.value;
        } else if (token.key == "tcontext") {
            denial.tcontext = token.value;
        } else if (token.key == "tclass") {
            denial.tclass = token.value;
        } else if (token.key == "permissive") {
            denial.permissive = token.value == "1";
        }
    }

    denial.stype = TypeOfContext(denial.scontext);
    denial.ttype = TypeOfContext(denial.tcontext);
    if (denial.stype.empty() || denial.ttype.empty() || denial.tclass.empty()) return std::nullopt;

    // The class is needed to tell a hex-encoded string from a plain one.
    for (Token& token : tokens) {
        if (token.key == "scontext" || token.key == "tcontext" || token.key == "tclass" ||
            token.key == "permissive") {
            continue;
        }
        bool decodable = !token.quoted &&
                         (token.key == "path" || ((token.key == "name" || token.key == "comm") &&
                                                  !IsServiceManagerClass(denial.tclass)));
        if (decodable) {
            if (auto decoded = DecodeAuditHex(token.value)) token.value = *decoded;
        }
        denial.fields[token.key] = std::move(token.value);
    }
    return denial;
}

}  // namespace selogger
