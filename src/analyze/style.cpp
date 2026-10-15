/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "analyze/style.h"

#include <android-base/strings.h>

#include <algorithm>
#include <cctype>

namespace selogger {

namespace {

std::string Casefold(std::string text) {
    for (char& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}

// "get_prop(" but not "allow".
bool IsMacroCall(const std::string& line) {
    if (line.empty() || !(std::islower(static_cast<unsigned char>(line[0])) || line[0] == '_'))
        return false;
    size_t i = 0;
    while (i < line.size() &&
           (std::islower(static_cast<unsigned char>(line[i])) ||
            std::isdigit(static_cast<unsigned char>(line[i])) || line[i] == '_')) {
        i++;
    }
    return i < line.size() && line[i] == '(';
}

// The first whitespace-separated field(s) a contexts file is sorted by.
std::string FirstField(const std::string& line) {
    return line.substr(0, line.find_first_of(" \t"));
}

// Fields 2 and 3 of "genfscon fs path context".
std::pair<std::string, std::string> GenfsKey(const std::string& line) {
    std::vector<std::string> fields = android::base::Tokenize(line, " \t");
    if (fields.size() < 3) return {line, ""};
    return {Casefold(fields[1]), Casefold(fields[2])};
}

// Mirrors file_contexts_out_of_order() of the checker: true if `current`
// has to come before `previous`.
bool OutOfOrder(const std::string& previous, const std::string& current) {
    std::vector<std::string> earlier = android::base::Split(previous, "/");
    std::vector<std::string> later = android::base::Split(current, "/");
    size_t common = std::min(earlier.size(), later.size());
    for (size_t index = 0; index < common; index++) {
        if (earlier[index] == later[index]) continue;
        bool left_dir = index + 1 < earlier.size();
        bool right_dir = index + 1 < later.size();
        if (left_dir != right_dir) return right_dir;
        return later[index] < earlier[index];
    }
    return later.size() < earlier.size();
}

}  // namespace

bool TeLineLess(const std::string& a, const std::string& b) {
    // The checker compares the code of a line without its trailing comment.
    auto code = [](const std::string& line) {
        return android::base::Trim(line.substr(0, line.find('#')));
    };
    std::string ca = code(a);
    std::string cb = code(b);
    return std::make_pair(IsMacroCall(ca), Casefold(ca)) <
           std::make_pair(IsMacroCall(cb), Casefold(cb));
}

bool FileContextsLess(const std::string& a, const std::string& b) {
    return OutOfOrder(Casefold(b), Casefold(a));
}

std::string FormatContextsLine(const std::string& file, const std::string& line) {
    if (file == "genfs_contexts" || file == "file_contexts") {
        // The context is the last field.
        size_t space = line.rfind(' ');
        if (space == std::string::npos) return line;
        return line.substr(0, space) + "\t" + line.substr(space + 1);
    }
    if (file.ends_with("_contexts")) {
        // Name, then context and options.
        size_t space = line.find(' ');
        if (space == std::string::npos) return line;
        return line.substr(0, space) + "\t" + line.substr(space + 1);
    }
    return line;
}

void SortLines(const std::string& file, std::vector<std::string>* lines) {
    if (file == "file_contexts") {
        std::stable_sort(lines->begin(), lines->end(),
                         [](const std::string& a, const std::string& b) {
                             return FileContextsLess(FirstField(a), FirstField(b));
                         });
    } else if (file == "genfs_contexts") {
        std::stable_sort(lines->begin(), lines->end(),
                         [](const std::string& a, const std::string& b) {
                             return GenfsKey(a) < GenfsKey(b);
                         });
    } else if (file.ends_with("_contexts")) {
        std::stable_sort(lines->begin(), lines->end(),
                         [](const std::string& a, const std::string& b) {
                             return Casefold(FirstField(a)) < Casefold(FirstField(b));
                         });
    } else {
        std::stable_sort(lines->begin(), lines->end(), TeLineLess);
    }
}

}  // namespace selogger
