/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace selogger {

enum class ServiceKind { kService, kHwService, kVndService };

// What the labelers need to ask the running device. The Android
// implementation answers from the device's own *_contexts files and file
// systems; tests use a fake.
class DeviceInfo {
  public:
    virtual ~DeviceInfo() = default;

    // The type file_contexts gives a path, or "" if there is no match. tclass
    // is the SELinux object class ("file", "dir", "chr_file", ...).
    virtual std::string FileLabel(const std::string& path, const std::string& tclass) const = 0;
    // The type property_contexts gives a property name, or "".
    virtual std::string PropertyLabel(const std::string& name) const = 0;
    // The type the matching *service_contexts gives a service, or "".
    virtual std::string ServiceLabel(ServiceKind kind, const std::string& name) const = 0;
    // Names of the properties that currently have a type.
    virtual std::vector<std::string> PropertiesLabeled(const std::string& type) const = 0;

    // The path of an inode on the file system the kernel calls `dev`; "" if
    // it cannot be found (or no longer exists).
    virtual std::string ResolveInode(const std::string& dev, uint64_t ino,
                                     const std::string& name) const = 0;
    // The path with symbolic links resolved; the argument if that fails.
    virtual std::string RealPath(const std::string& path) const = 0;
    // Where a pseudo file system ("sysfs", "debugfs", ...) is mounted; "" if
    // it is not.
    virtual std::string MountPoint(const std::string& fs) const = 0;
    // Executables in the usual bin directories whose name starts with the
    // (15 character) process name.
    virtual std::vector<std::string> FindExecutables(const std::string& comm) const = 0;
};

}  // namespace selogger
