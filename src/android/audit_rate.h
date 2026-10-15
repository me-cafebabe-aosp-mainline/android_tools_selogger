/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>

namespace selogger {

// Sets the kernel's limit on audit messages per second; 0 removes the limit.
//
// Needs CAP_AUDIT_CONTROL. This is what logd's auditctl does at the end of
// boot (5 per second unless persist.logd.audit.rate says otherwise); the
// property itself belongs to the system partition, so vendor code talks to
// the kernel directly.
bool SetAuditRateLimit(uint32_t rate);

}  // namespace selogger
