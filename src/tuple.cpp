/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "tuple.h"

#include <algorithm>

namespace selogger {

namespace {

// Adds a value to a bounded set. Returns true if the set changed.
bool Insert(std::set<std::string>& set, const std::string& value, size_t max) {
    if (value.empty() || set.contains(value) || set.size() >= max) return false;
    set.insert(value);
    return true;
}

}  // namespace

std::vector<std::pair<std::string, std::string>> ExtractHints(const AvcDenial& d) {
    std::vector<std::pair<std::string, std::string>> hints;
    auto add = [&](const char* kind, const std::string& value) {
        if (!value.empty()) hints.emplace_back(kind, value);
    };

    if (d.tclass == "service_manager") {
        add(kHintService, d.Get("name"));
    } else if (d.tclass == "hwservice_manager") {
        add(kHintHwService, d.Get("interface"));
        add(kHintHwService, d.Get("name"));
    } else {
        add(kHintName, d.Get("name"));
    }
    add(kHintPath, d.Get("path"));
    add(kHintProperty, d.Get("property"));
    add(kHintComm, d.Get("comm"));
    if (d.Get("path").empty() && !d.Get("ino").empty()) {
        add(kHintDevIno, d.Get("dev") + ":" + d.Get("ino") + ":" + d.Get("name"));
    }
    if (!d.Get("lport").empty()) add(kHintPort, d.tclass + ":" + d.Get("lport"));
    if (!d.Get("dest").empty()) add(kHintPort, d.tclass + ":" + d.Get("dest"));
    return hints;
}

TupleTable::Change TupleTable::Add(const AvcDenial& denial, const Observation& obs) {
    TupleKey key{denial.stype, denial.ttype, denial.tclass};
    auto [it, inserted] = tuples_.try_emplace(key);
    Tuple& tuple = it->second;
    if (inserted) {
        tuple.key = key;
        tuple.first_seen = obs.time_sec;
    }

    bool structure = inserted;
    for (const std::string& perm : denial.perms) {
        structure |= tuple.perms.insert(perm).second;
    }
    // A tuple with unbounded ioctls would grow without limit, so they share
    // the hint cap.
    structure |= Insert(tuple.ioctls, denial.Get("ioctlcmd"), max_hints_ * 4);
    for (const auto& [kind, value] : ExtractHints(denial)) {
        structure |= Insert(tuple.hints[kind], value, max_hints_);
    }
    if (denial.permissive) {
        structure |= !tuple.saw_permissive;
        tuple.saw_permissive = true;
    } else {
        structure |= !tuple.saw_enforcing;
        tuple.saw_enforcing = true;
    }

    tuple.count++;
    tuple.last_seen = std::max(tuple.last_seen, obs.time_sec);
    if (!obs.boot_id.empty() && tuple.last_boot != obs.boot_id) {
        tuple.last_boot = obs.boot_id;
        tuple.boots++;
    }

    if (structure) {
        tuple.dirty_structure = true;
    } else {
        tuple.dirty_count = true;
    }

    if (tuples_.size() > max_tuples_) EvictOldest();
    return structure ? Change::kStructure : Change::kCount;
}

void TupleTable::Put(Tuple tuple) {
    TupleKey key = tuple.key;
    tuple.dirty_structure = false;
    tuple.dirty_count = false;
    tuples_[key] = std::move(tuple);
    if (tuples_.size() > max_tuples_) EvictOldest();
}

std::vector<Tuple> TupleTable::TakeDirty(bool include_counts) {
    std::vector<Tuple> out;
    for (auto& [key, tuple] : tuples_) {
        if (tuple.dirty_structure || (include_counts && tuple.dirty_count)) {
            out.push_back(tuple);
            tuple.dirty_structure = false;
            tuple.dirty_count = false;
        }
    }
    return out;
}

bool TupleTable::HasDirty(bool include_counts) const {
    return std::any_of(tuples_.begin(), tuples_.end(), [&](const auto& entry) {
        return entry.second.dirty_structure || (include_counts && entry.second.dirty_count);
    });
}

void TupleTable::Clear() {
    tuples_.clear();
    evicted_ = 0;
}

void TupleTable::EvictOldest() {
    // Drop a tenth at once so a stream of new tuples does not rescan the
    // table on every insert.
    std::vector<std::pair<int64_t, TupleKey>> by_age;
    by_age.reserve(tuples_.size());
    for (const auto& [key, tuple] : tuples_) by_age.emplace_back(tuple.last_seen, key);
    size_t drop = std::max<size_t>(1, tuples_.size() / 10);
    std::nth_element(by_age.begin(), by_age.begin() + drop - 1, by_age.end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    for (size_t i = 0; i < drop; i++) tuples_.erase(by_age[i].second);
    evicted_ += drop;
}

}  // namespace selogger
