/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "analyze/policy_db.h"

#include <algorithm>
#include <cctype>

namespace selogger {

namespace {

constexpr int kMaxDepth = 16;

class Reader {
  public:
    explicit Reader(std::string_view text) : text_(text) {}

    // Calls on_form(head, expr) for every top-level form whose head atom is
    // in `interesting`; other forms are skipped without being built.
    template <typename Fn>
    void ForEachForm(const std::set<std::string_view>& interesting, Fn on_form) {
        while (SkipSpace()) {
            if (text_[pos_] != '(') {
                pos_++;
                continue;
            }
            size_t start = pos_;
            pos_++;
            SkipSpace();
            std::string_view head = ReadAtom();
            if (!interesting.contains(head)) {
                pos_ = start;
                SkipForm();
                continue;
            }
            pos_ = start;
            on_form(head, ReadExpr());
        }
    }

  private:
    // Skips whitespace and comments; false at the end of the text.
    bool SkipSpace() {
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            if (c == ';') {
                while (pos_ < text_.size() && text_[pos_] != '\n') pos_++;
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                pos_++;
            } else {
                return true;
            }
        }
        return false;
    }

    std::string_view ReadAtom() {
        size_t start = pos_;
        if (pos_ < text_.size() && text_[pos_] == '"') {
            pos_++;
            while (pos_ < text_.size() && text_[pos_] != '"') pos_++;
            if (pos_ < text_.size()) pos_++;
            return text_.substr(start + 1, pos_ - start - 2);
        }
        while (pos_ < text_.size() && !std::isspace(static_cast<unsigned char>(text_[pos_])) &&
               text_[pos_] != '(' && text_[pos_] != ')') {
            pos_++;
        }
        return text_.substr(start, pos_ - start);
    }

    PolicyDb::Expr ReadExprImpl();

    void SkipForm() {
        int depth = 0;
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            if (c == '"') {
                ReadAtom();
                continue;
            }
            if (c == ';') {
                SkipSpace();
                continue;
            }
            pos_++;
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return;
            }
        }
    }

  public:
    PolicyDb::Expr ReadExpr() { return ReadExprImpl(); }

  private:
    std::string_view text_;
    size_t pos_ = 0;
};

PolicyDb::Expr Reader::ReadExprImpl() {
    PolicyDb::Expr expr;
    if (!SkipSpace()) return expr;
    if (text_[pos_] != '(') {
        expr.atom = std::string(ReadAtom());
        return expr;
    }
    expr.is_list = true;
    pos_++;
    while (SkipSpace() && text_[pos_] != ')') {
        expr.list.push_back(ReadExprImpl());
    }
    if (pos_ < text_.size()) pos_++;  // ')'
    return expr;
}

}  // namespace

std::string PolicyDb::StripVersion(const std::string& name, bool* versioned) const {
    *versioned = false;
    if (platform_version_.empty()) return name;
    std::string suffix = "_" + platform_version_;
    if (name.size() > suffix.size() && name.ends_with(suffix)) {
        *versioned = true;
        return name.substr(0, name.size() - suffix.size());
    }
    return name;
}

void PolicyDb::AddCil(std::string_view text, PolicyOrigin origin) {
    Reader reader(text);
    reader.ForEachForm(
            {"type", "typeattribute", "typeattributeset", "genfscon"},
            [&](std::string_view head, const Expr& form) {
                const auto& items = form.list;
                if (head == "type" && items.size() >= 2) {
                    type_origin_.emplace(items[1].atom, origin);
                } else if (head == "typeattribute" && items.size() >= 2) {
                    attributes_.insert(items[1].atom);
                } else if (head == "typeattributeset" && items.size() >= 3) {
                    definitions_[items[1].atom].push_back(items[2]);
                    members_.clear();
                } else if (head == "genfscon" && items.size() >= 4 && items[3].is_list &&
                           items[3].list.size() >= 3) {
                    genfs_.push_back({items[1].atom, items[2].atom, items[3].list[2].atom});
                }
            });

    // Versioned names in a vendor file are public platform types.
    if (origin == PolicyOrigin::kVendor && !platform_version_.empty()) {
        std::string suffix = "_" + platform_version_;
        size_t pos = 0;
        while ((pos = text.find(suffix, pos)) != std::string_view::npos) {
            size_t end = pos + suffix.size();
            size_t begin = pos;
            while (begin > 0 && (std::isalnum(static_cast<unsigned char>(text[begin - 1])) ||
                                 text[begin - 1] == '_')) {
                begin--;
            }
            bool boundary =
                    end >= text.size() ||
                    !(std::isalnum(static_cast<unsigned char>(text[end])) || text[end] == '_');
            if (boundary && begin < pos)
                public_types_.insert(std::string(text.substr(begin, pos - begin)));
            pos = end;
        }
    }
}

std::set<std::string> PolicyDb::Evaluate(const Expr& expr, int depth) const {
    std::set<std::string> out;
    if (depth > kMaxDepth) return out;
    if (!expr.is_list) {
        if (expr.atom.empty()) return out;
        bool versioned;
        std::string name = StripVersion(expr.atom, &versioned);
        if (!versioned && (attributes_.contains(name) || definitions_.contains(name))) {
            return Members(name, depth + 1);
        }
        out.insert(name);
        return out;
    }

    const auto& items = expr.list;
    if (items.empty()) return out;
    if (!items[0].is_list &&
        (items[0].atom == "and" || items[0].atom == "or" || items[0].atom == "xor" ||
         items[0].atom == "not" || items[0].atom == "all")) {
        const std::string& op = items[0].atom;
        if (op == "all") {
            for (const auto& [type, origin] : type_origin_) out.insert(type);
            return out;
        }
        if (op == "not") {
            std::set<std::string> inner;
            if (items.size() > 1) inner = Evaluate(items[1], depth + 1);
            for (const auto& [type, origin] : type_origin_) {
                if (!inner.contains(type)) out.insert(type);
            }
            return out;
        }
        for (size_t i = 1; i < items.size(); i++) {
            std::set<std::string> operand = Evaluate(items[i], depth + 1);
            if (i == 1) {
                out = std::move(operand);
            } else if (op == "or") {
                out.insert(operand.begin(), operand.end());
            } else if (op == "and") {
                std::set<std::string> both;
                std::set_intersection(out.begin(), out.end(), operand.begin(), operand.end(),
                                      std::inserter(both, both.begin()));
                out = std::move(both);
            } else {  // xor
                std::set<std::string> diff;
                std::set_symmetric_difference(out.begin(), out.end(), operand.begin(),
                                              operand.end(), std::inserter(diff, diff.begin()));
                out = std::move(diff);
            }
        }
        return out;
    }

    // A plain list is a union.
    for (const Expr& item : items) {
        std::set<std::string> part = Evaluate(item, depth + 1);
        out.insert(part.begin(), part.end());
    }
    return out;
}

const std::set<std::string>& PolicyDb::Members(const std::string& attribute, int depth) const {
    auto it = members_.find(attribute);
    if (it != members_.end()) return it->second;
    std::set<std::string> result;
    auto def = definitions_.find(attribute);
    if (def != definitions_.end() && depth <= kMaxDepth) {
        // Placeholder first, so a cycle ends instead of recursing forever.
        members_[attribute];
        for (const Expr& expr : def->second) {
            std::set<std::string> part = Evaluate(expr, depth + 1);
            result.insert(part.begin(), part.end());
        }
    }
    return members_[attribute] = std::move(result);
}

bool PolicyDb::HasAttribute(const std::string& type, const std::string& attribute) const {
    return Members(attribute, 0).contains(type);
}

std::set<std::string> PolicyDb::MembersOf(const std::string& attribute) const {
    return Members(attribute, 0);
}

std::optional<PolicyOrigin> PolicyDb::OriginOf(const std::string& type) const {
    auto it = type_origin_.find(type);
    if (it == type_origin_.end()) return std::nullopt;
    return it->second;
}

std::optional<GenfsEntry> PolicyDb::LookupGenfs(const std::string& fs,
                                                const std::string& path) const {
    const GenfsEntry* best = nullptr;
    for (const GenfsEntry& entry : genfs_) {
        if (entry.fs != fs || !path.starts_with(entry.path)) continue;
        // "/devices/foo" must not match "/devices/foobar".
        if (path.size() > entry.path.size() && entry.path.size() > 1 &&
            path[entry.path.size()] != '/' && entry.path.back() != '/') {
            continue;
        }
        if (!best || entry.path.size() > best->path.size()) best = &entry;
    }
    if (!best) return std::nullopt;
    return *best;
}

}  // namespace selogger
