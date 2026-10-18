/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "collector.h"

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <sys/stat.h>

#include <algorithm>

namespace selogger {

std::string FormatStatus(const CollectorStatus& s) {
    return android::base::StringPrintf(
            "collecting: %s\n"
            "tuples: %llu\n"
            "evicted: %llu\n"
            "journal_bytes: %llu\n"
            "denials_seen: %llu\n"
            "parse_failures: %llu\n"
            "kernel_lost: %llu\n"
            "seconds_since_new_tuple: %lld\n",
            s.collecting ? "yes" : "no", static_cast<unsigned long long>(s.tuples),
            static_cast<unsigned long long>(s.evicted),
            static_cast<unsigned long long>(s.journal_bytes),
            static_cast<unsigned long long>(s.denials_seen),
            static_cast<unsigned long long>(s.parse_failures),
            static_cast<unsigned long long>(s.kernel_lost),
            static_cast<long long>(s.seconds_since_new_tuple));
}

Collector::Collector(Config config, std::string boot_id)
    : config_(std::move(config)),
      boot_id_(std::move(boot_id)),
      table_(config_.max_tuples, config_.max_hints),
      journal_(config_.journal_path()) {}

bool Collector::Init(int64_t now) {
    std::lock_guard lock(mutex_);
    mkdir(config_.state_dir.c_str(), 0770);
    if (!journal_.Load(&table_, &meta_)) return false;
    last_new_tuple_ = now;
    // The count is per boot.
    if (meta_.lost_boot == boot_id_) {
        kernel_lost_ = meta_.kernel_lost;
    } else {
        meta_.kernel_lost = 0;
        meta_.lost_boot.clear();
    }
    LOG(INFO) << "Loaded " << table_.size() << " tuples from " << journal_.path();
    return true;
}

bool Collector::OnDenial(const AvcDenial& denial, uint64_t entry_ns, int64_t entry_time_s,
                         int64_t now) {
    std::lock_guard lock(mutex_);
    denials_seen_++;
    meta_.last_entry_ns = std::max(meta_.last_entry_ns, entry_ns);

    auto change = table_.Add(denial, {entry_time_s, boot_id_});
    bool wake = false;
    if (change == TupleTable::Change::kStructure) {
        last_new_tuple_ = now;
        if (structure_pending_since_ == 0) {
            structure_pending_since_ = now;
            wake = true;
        }
    }
    if (counts_pending_since_ == 0) {
        counts_pending_since_ = now;
        wake = true;
    }
    return wake;
}

bool Collector::OnKernelLost(uint64_t lost, int64_t now) {
    std::lock_guard lock(mutex_);
    if (lost <= kernel_lost_) return false;
    kernel_lost_ = lost;
    meta_.kernel_lost = lost;
    meta_.lost_boot = boot_id_;
    meta_dirty_ = true;
    if (structure_pending_since_ != 0) return false;
    structure_pending_since_ = now;
    return true;
}

void Collector::OnParseFailure() {
    std::lock_guard lock(mutex_);
    parse_failures_++;
}

int64_t Collector::NextDeadlineLocked(int64_t now) const {
    int64_t next = -1;
    auto consider = [&](int64_t deadline) {
        int64_t in = std::max<int64_t>(0, deadline - now);
        if (next < 0 || in < next) next = in;
    };
    if (structure_pending_since_ != 0) consider(structure_pending_since_ + config_.flush_delay_s);
    if (counts_pending_since_ != 0) {
        consider(counts_pending_since_ + config_.count_flush_interval_s);
    }
    if (collecting_ && config_.idle_timeout_s > 0) {
        consider(last_new_tuple_ + config_.idle_timeout_s);
    }
    return next;
}

Collector::TickResult Collector::Tick(int64_t now) {
    std::lock_guard lock(mutex_);
    TickResult result;

    bool counts_due = counts_pending_since_ != 0 &&
                      now - counts_pending_since_ >= config_.count_flush_interval_s;
    bool structure_due = structure_pending_since_ != 0 &&
                         now - structure_pending_since_ >= config_.flush_delay_s;
    if (counts_due || structure_due) FlushLocked(counts_due);

    if (collecting_ && config_.idle_timeout_s > 0 &&
        now - last_new_tuple_ >= config_.idle_timeout_s) {
        collecting_ = false;
        result.set_collecting = false;
        LOG(INFO) << "No new denial kinds for " << config_.idle_timeout_s << "s, going idle";
    }

    result.next_in_s = NextDeadlineLocked(now);
    return result;
}

bool Collector::FlushLocked(bool include_counts) {
    std::vector<Tuple> dirty = table_.TakeDirty(include_counts);
    structure_pending_since_ = 0;
    if (include_counts) counts_pending_since_ = 0;
    if (dirty.empty() && !meta_dirty_) return true;
    meta_dirty_ = false;

    bool ok = journal_.Append(dirty, meta_);
    if (ok && journal_.size_bytes() > config_.journal_max_bytes) {
        ok = journal_.Rewrite(table_, meta_);
    }
    if (!ok) LOG(ERROR) << "Cannot write " << journal_.path() << ", denials stay in memory";
    return ok;
}

bool Collector::Flush() {
    std::lock_guard lock(mutex_);
    return FlushLocked(true);
}

bool Collector::Clear() {
    std::lock_guard lock(mutex_);
    table_.Clear();
    structure_pending_since_ = 0;
    counts_pending_since_ = 0;
    return journal_.Remove();
}

void Collector::SetCollecting(bool collecting, int64_t now) {
    std::lock_guard lock(mutex_);
    collecting_ = collecting;
    if (collecting) last_new_tuple_ = now;
}

bool Collector::collecting() const {
    std::lock_guard lock(mutex_);
    return collecting_;
}

CollectorStatus Collector::Status(int64_t now) const {
    std::lock_guard lock(mutex_);
    CollectorStatus s;
    s.tuples = table_.size();
    s.evicted = table_.evicted();
    s.journal_bytes = journal_.size_bytes();
    s.denials_seen = denials_seen_;
    s.parse_failures = parse_failures_;
    s.kernel_lost = kernel_lost_;
    s.collecting = collecting_;
    s.seconds_since_new_tuple = now - last_new_tuple_;
    return s;
}

uint64_t Collector::resume_ns() const {
    std::lock_guard lock(mutex_);
    return meta_.last_entry_ns;
}

}  // namespace selogger
