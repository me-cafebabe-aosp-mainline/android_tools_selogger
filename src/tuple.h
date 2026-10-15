/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "avc.h"

namespace selogger {

// Denials are aggregated by who was denied what on which class of object.
struct TupleKey {
    std::string stype;
    std::string ttype;
    std::string tclass;

    bool operator==(const TupleKey& other) const = default;
    bool operator<(const TupleKey& other) const {
        return std::tie(stype, ttype, tclass) < std::tie(other.stype, other.ttype, other.tclass);
    }
};

struct TupleKeyHash {
    size_t operator()(const TupleKey& key) const {
        std::hash<std::string> h;
        return h(key.stype) * 31 * 31 + h(key.ttype) * 31 + h(key.tclass);
    }
};

// Kinds of identifying details kept next to a tuple, for the labelers.
inline constexpr char kHintPath[] = "path";        // object path from the kernel
inline constexpr char kHintName[] = "name";        // last path component, or a context
inline constexpr char kHintProperty[] = "prop";    // property name
inline constexpr char kHintService[] = "svc";      // servicemanager service name
inline constexpr char kHintHwService[] = "hwsvc";  // hwservicemanager interface
inline constexpr char kHintComm[] = "comm";        // process name
inline constexpr char kHintDevIno[] = "devino";    // "dev:ino:name" when no path is known
inline constexpr char kHintPort[] = "port";        // "proto:port" for socket denials

struct Tuple {
    TupleKey key;
    std::set<std::string> perms;
    // ioctl commands from "ioctlcmd=", as written by the kernel (0x...).
    std::set<std::string> ioctls;
    std::map<std::string, std::set<std::string>> hints;
    uint64_t count = 0;
    int64_t first_seen = 0;  // seconds since the epoch
    int64_t last_seen = 0;
    bool saw_enforcing = false;
    bool saw_permissive = false;
    // Number of boots the tuple was seen in, and the last of them.
    uint32_t boots = 0;
    std::string last_boot;

    // Not persisted: what has to be written out.
    bool dirty_structure = false;
    bool dirty_count = false;
};

// Where and when a denial was seen.
struct Observation {
    int64_t time_sec = 0;
    std::string boot_id;  // short identifier of the current boot
};

// The identifying details of a denial, as (kind, value) pairs.
std::vector<std::pair<std::string, std::string>> ExtractHints(const AvcDenial& denial);

class TupleTable {
  public:
    enum class Change {
        kNone,
        kCount,      // only counters moved
        kStructure,  // new tuple, permission, ioctl or hint
    };

    TupleTable(size_t max_tuples, size_t max_hints)
        : max_tuples_(max_tuples), max_hints_(max_hints) {}

    Change Add(const AvcDenial& denial, const Observation& obs);

    // Inserts or replaces a tuple loaded from disk; it is not marked dirty.
    void Put(Tuple tuple);

    // Returns copies of the tuples that need writing and clears their flags.
    // Count-only changes are returned only if include_counts is set.
    std::vector<Tuple> TakeDirty(bool include_counts);

    void Clear();

    const std::unordered_map<TupleKey, Tuple, TupleKeyHash>& tuples() const { return tuples_; }
    size_t size() const { return tuples_.size(); }
    uint64_t evicted() const { return evicted_; }
    bool HasDirty(bool include_counts) const;

  private:
    void EvictOldest();

    size_t max_tuples_;
    size_t max_hints_;
    uint64_t evicted_ = 0;
    std::unordered_map<TupleKey, Tuple, TupleKeyHash> tuples_;
};

}  // namespace selogger
