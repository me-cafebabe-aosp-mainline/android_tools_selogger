/*
 * SPDX-FileCopyrightText: The LineageOS Project
 * SPDX-License-Identifier: Apache-2.0
 */

#include "journal.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace selogger {

namespace {

constexpr char kHeader[] = "#selogger-journal 1\n";
// The state directory is setgid to the group that runs the command line.
constexpr mode_t kFileMode = 0640;

std::string Escape(std::string_view in) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : in) {
        if (c == '%' || c < 0x20 || c == 0x7f) {
            out += '%';
            out += kHex[c >> 4];
            out += kHex[c & 0xf];
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string Unescape(std::string_view in) {
    auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    for (size_t i = 0; i < in.size(); i++) {
        if (in[i] == '%' && i + 2 < in.size() && hex(in[i + 1]) >= 0 && hex(in[i + 2]) >= 0) {
            out += static_cast<char>(hex(in[i + 1]) * 16 + hex(in[i + 2]));
            i += 2;
        } else {
            out += in[i];
        }
    }
    return out;
}

std::set<std::string> SplitSet(const std::string& joined) {
    std::set<std::string> out;
    for (const std::string& item : android::base::Split(joined, ",")) {
        if (!item.empty()) out.insert(item);
    }
    return out;
}

}  // namespace

std::string SerializeTuple(const Tuple& t) {
    std::string line = "T";
    auto item = [&](std::string_view key, std::string_view value) {
        line += '\t';
        line += key;
        line += '=';
        line += Escape(value);
    };
    item("st", t.key.stype);
    item("tt", t.key.ttype);
    item("tc", t.key.tclass);
    item("p", android::base::Join(t.perms, ','));
    if (!t.ioctls.empty()) item("x", android::base::Join(t.ioctls, ','));
    item("n", std::to_string(t.count));
    item("f", std::to_string(t.first_seen));
    item("l", std::to_string(t.last_seen));
    item("fl", std::to_string((t.saw_enforcing ? 1 : 0) | (t.saw_permissive ? 2 : 0)));
    item("bt", std::to_string(t.boots));
    if (!t.last_boot.empty()) item("lb", t.last_boot);
    for (const auto& [kind, values] : t.hints) {
        for (const std::string& value : values) item("h." + kind, value);
    }
    item("e", "1");
    line += '\n';
    return line;
}

std::optional<Tuple> ParseTuple(std::string_view line) {
    if (line.empty() || line[0] != 'T') return std::nullopt;
    Tuple t;
    bool complete = false;
    for (const std::string& field : android::base::Split(std::string(line), "\t")) {
        size_t eq = field.find('=');
        if (eq == std::string::npos) continue;
        std::string key = field.substr(0, eq);
        std::string value = Unescape(field.substr(eq + 1));
        if (key == "st") {
            t.key.stype = value;
        } else if (key == "tt") {
            t.key.ttype = value;
        } else if (key == "tc") {
            t.key.tclass = value;
        } else if (key == "p") {
            t.perms = SplitSet(value);
        } else if (key == "x") {
            t.ioctls = SplitSet(value);
        } else if (key == "n") {
            android::base::ParseUint(value, &t.count);
        } else if (key == "f") {
            android::base::ParseInt(value, &t.first_seen);
        } else if (key == "l") {
            android::base::ParseInt(value, &t.last_seen);
        } else if (key == "fl") {
            uint32_t flags = 0;
            android::base::ParseUint(value, &flags);
            t.saw_enforcing = flags & 1;
            t.saw_permissive = flags & 2;
        } else if (key == "bt") {
            android::base::ParseUint(value, &t.boots);
        } else if (key == "lb") {
            t.last_boot = value;
        } else if (key.starts_with("h.")) {
            t.hints[key.substr(2)].insert(value);
        }
        if (key == "e") complete = true;
    }
    // The end marker is missing on a record cut short by a crash.
    if (!complete || t.key.stype.empty() || t.key.ttype.empty() || t.key.tclass.empty() ||
        t.perms.empty()) {
        return std::nullopt;
    }
    return t;
}

std::string SerializeMeta(const JournalMeta& meta) {
    return "M\tlast_ns=" + std::to_string(meta.last_entry_ns) + "\n";
}

bool Journal::Load(TupleTable* table, JournalMeta* meta) {
    std::string content;
    if (!android::base::ReadFileToString(path_, &content)) {
        if (errno == ENOENT) {
            size_bytes_ = 0;
            return true;
        }
        PLOG(ERROR) << "Cannot read " << path_;
        return false;
    }
    size_bytes_ = content.size();

    size_t skipped = 0;
    for (const std::string& line : android::base::Split(content, "\n")) {
        if (line.empty() || line[0] == '#') continue;
        if (line[0] == 'M') {
            for (const std::string& field : android::base::Split(line, "\t")) {
                if (field.starts_with("last_ns=")) {
                    android::base::ParseUint(field.substr(8), &meta->last_entry_ns);
                }
            }
        } else if (auto tuple = ParseTuple(line)) {
            table->Put(std::move(*tuple));
        } else {
            skipped++;
        }
    }
    if (skipped) LOG(WARNING) << "Skipped " << skipped << " damaged lines in " << path_;
    return true;
}

bool Journal::Append(const std::vector<Tuple>& tuples, const JournalMeta& meta) {
    std::string data;
    // A new file starts with the format header.
    struct stat st;
    if (stat(path_.c_str(), &st) != 0 || st.st_size == 0) data = kHeader;
    for (const Tuple& tuple : tuples) data += SerializeTuple(tuple);
    data += SerializeMeta(meta);

    android::base::unique_fd fd(
            open(path_.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, kFileMode));
    if (fd < 0) {
        PLOG(ERROR) << "Cannot open " << path_;
        return false;
    }
    // Services run with a umask that would drop the group read bit.
    fchmod(fd, kFileMode);
    // One write, so concurrent readers see whole lines.
    if (!android::base::WriteFully(fd, data.data(), data.size())) {
        PLOG(ERROR) << "Cannot append to " << path_;
        return false;
    }
    size_bytes_ += data.size();
    return true;
}

bool Journal::Rewrite(const TupleTable& table, const JournalMeta& meta) {
    std::string data = kHeader;
    for (const auto& [key, tuple] : table.tuples()) data += SerializeTuple(tuple);
    data += SerializeMeta(meta);

    std::string tmp = path_ + ".tmp";
    // Owner and group stay as the directory gives them.
    if (!android::base::WriteStringToFile(data, tmp, kFileMode, static_cast<uid_t>(-1),
                                          static_cast<gid_t>(-1))) {
        PLOG(ERROR) << "Cannot write " << tmp;
        return false;
    }
    if (rename(tmp.c_str(), path_.c_str()) != 0) {
        PLOG(ERROR) << "Cannot rename " << tmp << " to " << path_;
        unlink(tmp.c_str());
        return false;
    }
    size_bytes_ = data.size();
    return true;
}

bool Journal::Remove() {
    size_bytes_ = 0;
    if (unlink(path_.c_str()) != 0 && errno != ENOENT) {
        PLOG(ERROR) << "Cannot remove " << path_;
        return false;
    }
    return true;
}

}  // namespace selogger
