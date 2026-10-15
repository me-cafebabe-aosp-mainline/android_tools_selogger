/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "tuple.h"

namespace selogger {

// State that is not part of a tuple.
struct JournalMeta {
    // Time of the newest log entry processed, to resume reading after a
    // restart.
    uint64_t last_entry_ns = 0;
};

// One line of the journal.
std::string SerializeTuple(const Tuple& tuple);
std::optional<Tuple> ParseTuple(std::string_view line);
std::string SerializeMeta(const JournalMeta& meta);

// The persistent copy of the tuple table.
//
// A text file with one full tuple per line. Updates are appended and a later
// line replaces an earlier one with the same key, so a crash can only lose
// the tail of the file. Rewrite() drops the superseded lines.
class Journal {
  public:
    explicit Journal(std::string path) : path_(std::move(path)) {}

    // Reads the file into the table. A missing file is an empty journal; lines
    // that do not parse are skipped.
    bool Load(TupleTable* table, JournalMeta* meta);

    bool Append(const std::vector<Tuple>& tuples, const JournalMeta& meta);

    // Replaces the file with one line per tuple, atomically.
    bool Rewrite(const TupleTable& table, const JournalMeta& meta);

    bool Remove();

    // Size of the file as of the last Load/Append/Rewrite.
    uint64_t size_bytes() const { return size_bytes_; }
    const std::string& path() const { return path_; }

  private:
    std::string path_;
    uint64_t size_bytes_ = 0;
};

}  // namespace selogger
