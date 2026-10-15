/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <map>
#include <set>
#include <string>

#include "analyze/macros.h"
#include "analyze/policy_db.h"

namespace selogger {

// The device's policy plus the types the labelers propose.
class PolicyTypes : public TypeInfo {
  public:
    PolicyTypes(const PolicyDb* policy,
                const std::map<std::string, std::set<std::string>>& proposed)
        : policy_(policy), proposed_(proposed) {}

    bool HasAttribute(const std::string& type, const std::string& attribute) const override {
        auto it = proposed_.find(type);
        if (it != proposed_.end()) return it->second.contains(attribute);
        return policy_ && policy_->HasAttribute(type, attribute);
    }

  private:
    const PolicyDb* policy_;
    const std::map<std::string, std::set<std::string>>& proposed_;
};

}  // namespace selogger
