/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/daemon.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include "android/audit_rate.h"
#include "android/control.h"
#include "android/logd_reader.h"
#include "avc.h"
#include "events.h"

namespace selogger {

namespace {

constexpr char kStateProperty[] = "vendor.selogger.state";
// Someone else (logd's auditctl at the end of boot) changing the rate while
// collecting is put right once per this many seconds, no more.
constexpr int64_t kRateFixInterval = 30;

}  // namespace

int64_t MonotonicSeconds() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

Daemon::Daemon(Config config, std::string boot_id)
    : config_(config), collector_(std::move(config), std::move(boot_id)) {}

void Daemon::Kick() {
    {
        std::lock_guard lock(wake_mutex_);
        kick_ = true;
    }
    wake_cv_.notify_one();
}

void Daemon::Stop() {
    stop_ = true;
    Kick();
}

void Daemon::ApplyState(bool collecting) {
    uint32_t rate = collecting ? config_.collect_audit_rate : config_.idle_audit_rate;
    last_rate_fix_ = MonotonicSeconds();
    if (!SetAuditRateLimit(rate)) {
        LOG(WARNING) << "Audit rate limit unchanged: denials may be dropped by the kernel";
    }
    android::base::SetProperty(kStateProperty, collecting ? "collecting" : "idle");
}

void Daemon::HandleRateChange(uint32_t rate) {
    if (!collector_.collecting() || rate == config_.collect_audit_rate) return;
    int64_t now = MonotonicSeconds();
    if (now - last_rate_fix_ < kRateFixInterval) return;
    LOG(INFO) << "Audit rate limit was set to " << rate << ", restoring "
              << config_.collect_audit_rate;
    ApplyState(true);
}

void Daemon::HandleEntry(const LogEntry& entry) {
    if (entry.log_id == kLogIdKernel) {
        if (auto lost = ParseAuditLost(entry.payload)) collector_.OnKernelLost(*lost);
        return;
    }

    auto message = DecodeAuditEvent(entry.payload);
    if (!message) return;
    if (auto rate = ParseRateLimitChange(*message)) {
        HandleRateChange(*rate);
        return;
    }

    auto denial = ParseAvc(*message);
    if (!denial) {
        if (message->find("avc:") != std::string_view::npos &&
            message->find("denied") != std::string_view::npos) {
            LOG(WARNING) << "Cannot parse: " << *message;
            collector_.OnParseFailure();
        }
        return;
    }
    if (collector_.OnDenial(*denial, entry.ns(), entry.sec, MonotonicSeconds())) Kick();
}

void Daemon::ReaderLoop() {
    std::vector<uint32_t> ids = {kLogIdEvents};
    if (config_.watch_audit_lost) ids.push_back(kLogIdKernel);
    LogdReader reader(ids);

    int backoff_s = 1;
    while (!stop_) {
        if (!reader.Open(collector_.resume_ns())) {
            std::this_thread::sleep_for(std::chrono::seconds(backoff_s));
            backoff_s = std::min(backoff_s * 2, 30);
            continue;
        }
        backoff_s = 1;

        LogEntry entry;
        while (reader.Read(&entry)) HandleEntry(entry);
        LOG(WARNING) << "Lost the connection to logd, reconnecting";
        reader.Close();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

std::string Daemon::HandleCommand(const std::string& command) {
    int64_t now = MonotonicSeconds();
    if (command == "status") {
        return FormatStatus(collector_.Status(now));
    } else if (command == "flush") {
        return collector_.Flush() ? "ok\n" : "error: cannot write the journal\n";
    } else if (command == "clear") {
        return collector_.Clear() ? "ok\n" : "error: cannot remove the journal\n";
    } else if (command == "collect on" || command == "collect off") {
        bool on = command == "collect on";
        collector_.SetCollecting(on, now);
        ApplyState(on);
        Kick();  // the idle timer changes
        return "ok\n";
    }
    return "error: unknown command \"" + command + "\"\n";
}

void Daemon::ControlLoop() {
    ControlServer server([this](const std::string& command) { return HandleCommand(command); });
    if (!server.Run()) LOG(ERROR) << "Control socket stopped; the daemon keeps collecting";
}

int Daemon::Run() {
    // Signals are handled by one thread, so none of the others is interrupted.
    sigset_t signals;
    sigemptyset(&signals);
    sigaddset(&signals, SIGTERM);
    sigaddset(&signals, SIGINT);
    pthread_sigmask(SIG_BLOCK, &signals, nullptr);

    int64_t now = MonotonicSeconds();
    if (!collector_.Init(now)) {
        LOG(ERROR) << "Cannot use " << config_.state_dir;
        return 1;
    }
    collector_.SetCollecting(config_.start_collecting, now);
    ApplyState(config_.start_collecting);

    std::thread([this, signals] {
        int sig;
        sigwait(&signals, &sig);
        LOG(INFO) << "Stopping on signal " << sig;
        Stop();
    }).detach();
    std::thread([this] { ControlLoop(); }).detach();
    std::thread([this] { ReaderLoop(); }).detach();

    while (!stop_) {
        Collector::TickResult result = collector_.Tick(MonotonicSeconds());
        if (result.set_collecting.has_value()) ApplyState(*result.set_collecting);

        std::unique_lock lock(wake_mutex_);
        auto ready = [this] { return kick_ || stop_; };
        if (result.next_in_s < 0) {
            wake_cv_.wait(lock, ready);
        } else {
            wake_cv_.wait_for(lock, std::chrono::seconds(result.next_in_s), ready);
        }
        kick_ = false;
    }

    collector_.Flush();
    // Leave the kernel the way logd configured it.
    SetAuditRateLimit(config_.idle_audit_rate);
    android::base::SetProperty(kStateProperty, "stopped");
    _exit(0);
}

}  // namespace selogger
