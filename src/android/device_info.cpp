/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "android/device_info.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <dirent.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>

#include "avc.h"

namespace selogger {

namespace {

// Where each partition keeps its contexts files: <dir>/<prefix>_<name>.
struct Partition {
    const char* dir;
    const char* prefix;
};
const Partition kPartitions[] = {{"/system/etc/selinux", "plat"},
                                 {"/system_ext/etc/selinux", "system_ext"},
                                 {"/product/etc/selinux", "product"},
                                 {"/vendor/etc/selinux", "vendor"},
                                 {"/odm/etc/selinux", "odm"}};

// Executables of services and HALs.
const char* const kBinDirs[] = {"/vendor/bin",     "/vendor/bin/hw",     "/odm/bin",
                                "/odm/bin/hw",     "/system/bin",        "/system/bin/hw",
                                "/system_ext/bin", "/system_ext/bin/hw", "/product/bin",
                                "/product/bin/hw"};

// The kernel truncates process names to this many characters.
constexpr size_t kCommLength = 15;

// Walking a file system to find an inode is a last resort; bound it.
constexpr size_t kMaxWalkedEntries = 300000;
constexpr std::chrono::seconds kMaxWalkTime(5);

template <typename Fn>
void ForEachContextsFile(const char* name, Fn fn) {
    for (const Partition& partition : kPartitions) {
        std::string text;
        std::string path = std::string(partition.dir) + "/" + partition.prefix + "_" + name;
        if (android::base::ReadFileToString(path, &text)) fn(text);
    }
}

mode_t ModeOf(const std::string& tclass) {
    if (tclass == "dir") return S_IFDIR;
    if (tclass == "lnk_file") return S_IFLNK;
    if (tclass == "chr_file") return S_IFCHR;
    if (tclass == "blk_file") return S_IFBLK;
    if (tclass == "sock_file") return S_IFSOCK;
    if (tclass == "fifo_file") return S_IFIFO;
    return S_IFREG;
}

}  // namespace

AndroidDeviceInfo::AndroidDeviceInfo() {
    ForEachContextsFile("property_contexts",
                        [&](const std::string& text) { properties_.Add(text); });
    ForEachContextsFile("service_contexts", [&](const std::string& text) { services_.Add(text); });
    ForEachContextsFile("hwservice_contexts",
                        [&](const std::string& text) { hwservices_.Add(text); });
    std::string text;
    if (android::base::ReadFileToString("/vendor/etc/selinux/vndservice_contexts", &text)) {
        vndservices_.Add(text);
    }
    file_contexts_ = selinux_android_file_context_handle();
    if (!file_contexts_) LOG(WARNING) << "No file_contexts: existing file labels are unknown";
    LoadMounts();
}

void AndroidDeviceInfo::LoadMounts() {
    std::string text;
    if (!android::base::ReadFileToString("/proc/self/mountinfo", &text)) return;
    // id parent major:minor root mount_point options [optional...] - fs_type source super_options
    for (const std::string& line : android::base::Split(text, "\n")) {
        std::vector<std::string> fields = android::base::Tokenize(line, " ");
        auto separator = std::find(fields.begin(), fields.end(), "-");
        if (fields.size() < 7 || separator == fields.end() || separator + 1 == fields.end())
            continue;
        mounts_.push_back({fields[2], fields[4], *(separator + 1)});
    }
}

std::string AndroidDeviceInfo::FileLabel(const std::string& path, const std::string& tclass) const {
    if (!file_contexts_) return "";
    char* context = nullptr;
    if (selabel_lookup(file_contexts_, &context, path.c_str(), ModeOf(tclass)) != 0) return "";
    std::string type = TypeOfContext(context);
    freecon(context);
    return type;
}

std::string AndroidDeviceInfo::PropertyLabel(const std::string& name) const {
    return properties_.Lookup(name);
}

std::string AndroidDeviceInfo::ServiceLabel(ServiceKind kind, const std::string& name) const {
    switch (kind) {
        case ServiceKind::kService:
            return services_.Lookup(name);
        case ServiceKind::kHwService:
            return hwservices_.Lookup(name);
        case ServiceKind::kVndService:
            return vndservices_.Lookup(name);
    }
    return "";
}

std::vector<std::string> AndroidDeviceInfo::PropertiesLabeled(const std::string& type) const {
    struct Collect {
        const AndroidDeviceInfo* self;
        const std::string* type;
        std::vector<std::string> names;
    } collect{this, &type, {}};

    __system_property_foreach(
            [](const prop_info* info, void* cookie) {
                __system_property_read_callback(
                        info,
                        [](void* cookie, const char* name, const char*, uint32_t) {
                            auto* c = static_cast<Collect*>(cookie);
                            if (c->self->PropertyLabel(name) == *c->type) c->names.push_back(name);
                        },
                        cookie);
            },
            &collect);
    std::sort(collect.names.begin(), collect.names.end());
    return collect.names;
}

std::string AndroidDeviceInfo::ResolveInode(const std::string& dev, uint64_t ino,
                                            const std::string& name) const {
    // The kernel names a file system by its superblock id: a block device
    // name ("dm-4") or the file system type ("tmpfs").
    std::string numbers;
    std::string sys_dev;
    if (android::base::ReadFileToString("/sys/class/block/" + dev + "/dev", &sys_dev)) {
        numbers = android::base::Trim(sys_dev);
    }
    std::vector<std::string> roots;
    for (const Mount& mount : mounts_) {
        if ((!numbers.empty() && mount.device_numbers == numbers) ||
            (numbers.empty() && mount.fs_type == dev)) {
            roots.push_back(mount.mount_point);
        }
    }

    auto deadline = std::chrono::steady_clock::now() + kMaxWalkTime;
    size_t walked = 0;
    for (const std::string& root : roots) {
        struct stat root_stat;
        if (lstat(root.c_str(), &root_stat) != 0) continue;
        std::vector<std::string> pending = {root};
        while (!pending.empty()) {
            std::string dir = std::move(pending.back());
            pending.pop_back();
            DIR* handle = opendir(dir.c_str());
            if (!handle) continue;
            while (dirent* entry = readdir(handle)) {
                std::string child = (dir == "/" ? "" : dir) + "/" + entry->d_name;
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
                if (++walked > kMaxWalkedEntries || std::chrono::steady_clock::now() > deadline) {
                    closedir(handle);
                    LOG(WARNING) << "Gave up looking for inode " << ino << " on " << dev;
                    return "";
                }
                if (entry->d_ino == ino && (name.empty() || name == entry->d_name)) {
                    struct stat st;
                    if (lstat(child.c_str(), &st) == 0 && st.st_ino == ino &&
                        st.st_dev == root_stat.st_dev) {
                        closedir(handle);
                        return child;
                    }
                }
                if (entry->d_type == DT_DIR) {
                    struct stat st;
                    // Stay on the file system the denial is about.
                    if (lstat(child.c_str(), &st) == 0 && st.st_dev == root_stat.st_dev) {
                        pending.push_back(child);
                    }
                }
            }
            closedir(handle);
        }
    }
    return "";
}

std::string AndroidDeviceInfo::RealPath(const std::string& path) const {
    std::error_code error;
    std::filesystem::path real = std::filesystem::canonical(path, error);
    return error ? path : real.string();
}

std::string AndroidDeviceInfo::MountPoint(const std::string& fs) const {
    for (const Mount& mount : mounts_) {
        if (mount.fs_type == fs) return mount.mount_point;
    }
    return "";
}

std::vector<std::string> AndroidDeviceInfo::FindExecutables(const std::string& comm) const {
    std::vector<std::string> found;
    for (const char* dir : kBinDirs) {
        std::error_code error;
        for (const auto& entry : std::filesystem::directory_iterator(dir, error)) {
            std::string file = entry.path().filename().string();
            if (file.substr(0, kCommLength) != comm.substr(0, kCommLength)) continue;
            std::error_code type_error;
            if (entry.is_regular_file(type_error) || entry.is_symlink(type_error)) {
                // Binaries are often reachable through a bin -> bin/hw style
                // symlink as well; report each real file once.
                std::string real = RealPath(entry.path().string());
                if (std::find(found.begin(), found.end(), real) == found.end())
                    found.push_back(real);
            }
        }
    }
    return found;
}

}  // namespace selogger
