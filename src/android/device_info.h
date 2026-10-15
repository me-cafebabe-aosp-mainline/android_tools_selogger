/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <string>
#include <vector>

#include "label/contexts.h"
#include "label/device_info.h"

struct selabel_handle;

namespace selogger {

// Answers the labelers' questions from the files and file systems of the
// device the command runs on.
class AndroidDeviceInfo : public DeviceInfo {
  public:
    AndroidDeviceInfo();

    std::string FileLabel(const std::string& path, const std::string& tclass) const override;
    std::string PropertyLabel(const std::string& name) const override;
    std::string ServiceLabel(ServiceKind kind, const std::string& name) const override;
    std::vector<std::string> PropertiesLabeled(const std::string& type) const override;
    std::string ResolveInode(const std::string& dev, uint64_t ino,
                             const std::string& name) const override;
    std::string RealPath(const std::string& path) const override;
    std::string MountPoint(const std::string& fs) const override;
    std::vector<std::string> FindExecutables(const std::string& comm) const override;

  private:
    struct Mount {
        std::string device_numbers;  // "253:4"
        std::string mount_point;
        std::string fs_type;
    };

    void LoadMounts();

    PropertyContexts properties_;
    ServiceContexts services_;
    ServiceContexts hwservices_;
    ServiceContexts vndservices_;
    selabel_handle* file_contexts_ = nullptr;
    std::vector<Mount> mounts_;
};

}  // namespace selogger
