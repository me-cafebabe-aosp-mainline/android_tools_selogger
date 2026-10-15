#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#

"""Expand the output of "selogger dump" into the sepolicy files of a device tree.

The dump has one .te file per domain and the *_contexts files with the
labels it proposes. This tool puts them where they belong: new files are
created, and in files that exist the new rules and entries are added to the
section they belong in, in the order device/mainline/common/build/tools/
check_sepolicy.py expects, without duplicates. Nothing already in a file is
removed or changed, except that the permissions of an "allow" rule that is
there are extended.

  selogger_expand.py --pull --sepolicy-dir device/foo/bar/sepolicy/vendor
  selogger_expand.py --dump ./selogger-dump --sepolicy-dir ... --dry-run

Read REVIEW.md of the dump first: it says what needs a decision.
"""

import argparse
import difflib
import functools
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


DEVICE_DUMP_DIR = '/data/local/tmp/selogger-dump'
CHECKER = Path('device/mainline/common/build/tools/check_sepolicy.py')

# The same patterns the style check uses to find section titles.
HEADING = re.compile(r'^(#{1,3}) ([A-Za-z][A-Za-z0-9() _-]*)$')
MACRO_CALL = re.compile(r'^[a-z_][a-z_0-9]*\(')
RULE = re.compile(
    r'^(allow|allowxperm)\s+(\S+)\s+(\S+):(\S+)\s+(?:(ioctl)\s+)?(\{[^}]*\}|[^\s;{}]+)\s*;$')
TYPE_DECLARATION = re.compile(r'^\s*type\s+([A-Za-z0-9_]+)\s*[,;]')


class Error(Exception):
    pass


# Style

def parse_heading(line):
    """Return (depth, title) if the line is a section title, as the checker sees it."""
    match = HEADING.fullmatch(line.strip())
    if not match:
        return None
    words = match.group(2).split()
    if len(words) <= 4 or all(word[0].isupper() for word in words):
        return len(match.group(1)), match.group(2)
    return None


def is_entry(line):
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith('#')


def code_of(line):
    return line.partition('#')[0].strip()


def te_sort_key(line):
    code = code_of(line)
    return (bool(MACRO_CALL.match(code)), code.casefold())


def file_contexts_out_of_order(previous, current):
    """True if `current` has to come before `previous` (as in the checker)."""
    earlier = previous.split('/')
    later = current.split('/')
    for index, (left, right) in enumerate(zip(earlier, later)):
        if left == right:
            continue
        left_dir = index < len(earlier) - 1
        right_dir = index < len(later) - 1
        if left_dir != right_dir:
            return right_dir
        return right < left
    return len(later) < len(earlier)


def _file_contexts_cmp(a, b):
    a, b = a.split()[0].casefold(), b.split()[0].casefold()
    if file_contexts_out_of_order(b, a):
        return -1
    if file_contexts_out_of_order(a, b):
        return 1
    return 0


def entry_key(name, line):
    """What identifies an entry of a contexts file."""
    fields = line.split()
    if name == 'genfs_contexts':
        return tuple(fields[1:3])
    return (fields[0],)


def sort_entries(name, lines):
    if name == 'file_contexts':
        return sorted(lines, key=functools.cmp_to_key(_file_contexts_cmp))
    if name == 'genfs_contexts':
        return sorted(lines, key=lambda line: tuple(f.casefold() for f in line.split()[1:3]))
    if name.endswith('_contexts'):
        return sorted(lines, key=lambda line: line.split()[0].casefold())
    return sorted(lines, key=te_sort_key)


# Merging

class Report:
    def __init__(self):
        self.created = []
        self.updated = []
        self.unchanged = []
        self.added = 0
        self.extended = 0
        self.conflicts = []
        self.skipped_types = []
        self.skipped_platform = []

    def summary(self):
        lines = [f'Created {len(self.created)} files, updated {len(self.updated)}, '
                 f'{len(self.unchanged)} already had everything.',
                 f'Added {self.added} entries, extended the permissions of {self.extended} rules.']
        for conflict in self.conflicts:
            lines.append(f'Conflict, kept the existing entry: {conflict}')
        for skipped in self.skipped_types:
            lines.append(f'Skipped, already declared: {skipped}')
        if self.skipped_platform:
            lines.append('Not written, they belong to the platform sepolicy (use --platform-dir): ' +
                         ', '.join(self.skipped_platform))
        return '\n'.join(lines)


def parse_sections(text):
    """Split a dump file into [(title, [entry lines])] at its depth 1 titles."""
    sections = []
    for line in text.splitlines():
        heading = parse_heading(line)
        if heading and heading[0] == 1:
            sections.append((heading[1], []))
        elif sections and (is_entry(line) or line.strip().startswith('# ')):
            sections[-1][1].append(line)
    return sections


def _rule_parts(line):
    match = RULE.match(code_of(line))
    if not match:
        return None
    op, source, target, tclass, ioctl, perms = match.groups()
    key = (op, source, target, tclass, ioctl or '')
    return key, set(perms.strip('{} ').split())


def _render_rule(key, perms):
    op, source, target, tclass, ioctl = key
    if op == 'allowxperm':
        ordered = sorted(perms, key=lambda p: int(p, 16) if p.startswith('0x') else p)
    else:
        ordered = sorted(perms)
    text = ordered[0] if len(ordered) == 1 and op == 'allow' else '{ ' + ' '.join(ordered) + ' }'
    return f'{op} {source} {target}:{tclass} {(ioctl + " ") if ioctl else ""}{text};'


def normalize(line):
    return ' '.join(code_of(line).split())


def norm(line):
    """The line without comment and extra blanks; a comment line stands for itself."""
    return normalize(line) or line.strip()


class Merger:
    def __init__(self, name, report, declared_types):
        self.name = name
        self.report = report
        self.declared_types = declared_types
        self.is_te = name.endswith('.te')

    def _carries(self, line):
        # In .te files comments (the withheld rules) are carried over too.
        return is_entry(line) or (self.is_te and line.strip().startswith('#') and not parse_heading(line))

    def merge(self, existing, new):
        """Return (the file with permissions extended, entries to add).

        `existing` is the whole file: an entry is not new if it is anywhere in it.
        """
        existing = list(existing)
        to_add = []
        if self.is_te:
            seen = {norm(line) for line in existing if self._carries(line)}
        else:
            seen = {entry_key(self.name, line): line for line in existing if is_entry(line)}
        rules = {}
        if self.is_te:
            for index, line in enumerate(existing):
                parts = _rule_parts(line) if is_entry(line) else None
                if parts:
                    rules[parts[0]] = (index, parts[1])

        for line in new:
            if not self._carries(line):
                continue
            if self.is_te:
                parts = _rule_parts(line)
                if parts and parts[0] in rules:
                    index, perms = rules[parts[0]]
                    if not parts[1] <= perms:
                        existing[index] = _render_rule(parts[0], perms | parts[1])
                        rules[parts[0]] = (index, perms | parts[1])
                        self.report.extended += 1
                    continue
                if norm(line) in seen:
                    continue
                declared = TYPE_DECLARATION.match(line)
                if declared and declared.group(1) in self.declared_types:
                    self.report.skipped_types.append(declared.group(1))
                    continue
                seen.add(norm(line))
                if parts:
                    rules[parts[0]] = (-1, parts[1])
                if declared:
                    self.declared_types.add(declared.group(1))
            else:
                key = entry_key(self.name, line)
                if key in seen:
                    if seen[key].split() != line.split():
                        self.report.conflicts.append(f'{self.name}: {line.split()[0]} is "{seen[key].strip()}", '
                                                     f'the dump has "{line.strip()}"')
                    continue
                seen[key] = line
            to_add.append(line)
            self.report.added += 1
        return existing, to_add


def _section_bounds(lines, title):
    """Return (heading index, end index) of a depth 1 section, or None."""
    start = None
    for index, line in enumerate(lines):
        heading = parse_heading(line)
        if not heading or heading[0] != 1:
            continue
        if start is not None:
            return start, index
        if heading[1].casefold() == title.casefold():
            start = index
    return (start, len(lines)) if start is not None else None


def _insertion_point(lines, title):
    """Where a new depth 1 section goes: before the first title that sorts after it."""
    for index, line in enumerate(lines):
        heading = parse_heading(line)
        if heading and heading[0] == 1 and heading[1].casefold() > title.casefold():
            # Keep prose comments that lead up to that title with it.
            while index > 0 and lines[index - 1].strip().startswith('#') and not parse_heading(lines[index - 1]):
                index -= 1
            return index
    return len(lines)


def _is_sorted(name, entries):
    return entries == sort_entries(name, entries)


def merge_section(merger, lines, title, new):
    lines, to_add = merger.merge(lines, new)
    if not to_add:
        return lines

    bounds = _section_bounds(lines, title)
    if bounds is None:
        block = ['# ' + title] + sort_entries(merger.name, to_add)
        at = _insertion_point(lines, title)
        before = [''] if at > 0 and lines[at - 1].strip() else []
        after = [''] if at < len(lines) else []
        return lines[:at] + before + block + after + lines[at:]

    start, end = bounds
    body = lines[start + 1:end]
    trailing = 0
    while body and not body[-1].strip():
        body.pop()
        trailing += 1
    entries = [line for line in body if is_entry(line)]
    single_block = len(entries) == len(body)  # no blank lines, no comments
    if single_block and _is_sorted(merger.name, entries):
        new_body = sort_entries(merger.name, entries + to_add)
    else:
        # Keep what is there as it is and add a block of our own.
        separator = [''] if body and body[-1].strip() else []
        new_body = body + separator + sort_entries(merger.name, to_add)
    return lines[:start + 1] + new_body + [''] * trailing + lines[end:]


def merge_text(name, existing_text, dump_text, report, declared_types):
    """Return the new content of a file; None if there is nothing to write."""
    merger = Merger(name, report, declared_types)
    if existing_text is None:
        # The header of the dump, then its sections through the same merge,
        # so that what is already declared elsewhere is left out.
        lines = []
        for line in dump_text.splitlines():
            if parse_heading(line):
                break
            lines.append(line)
        while lines and not lines[-1].strip():
            lines.pop()
    else:
        lines = existing_text.splitlines()
    for title, entries in parse_sections(dump_text):
        lines = merge_section(merger, lines, title, entries)
    if existing_text is None and not any(is_entry(line) for line in lines):
        return None
    return '\n'.join(lines) + '\n'


def declared_types_in(directory):
    types = set()
    if directory.is_dir():
        for path in directory.rglob('*.te'):
            for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
                match = TYPE_DECLARATION.match(line)
                if match:
                    types.add(match.group(1))
    return types


def expand(dump_root, sepolicy_dir, platform_dir=None, dry_run=False, out=sys.stdout):
    """Merge the files of a dump into the directories. Returns (Report, touched paths)."""
    report = Report()
    touched = []
    declared = declared_types_in(sepolicy_dir)
    if platform_dir:
        declared |= declared_types_in(platform_dir)

    for home, target in (('vendor', sepolicy_dir), ('platform', platform_dir)):
        source_dir = dump_root / home
        if not source_dir.is_dir():
            continue
        for source in sorted(p for p in source_dir.rglob('*') if p.is_file()):
            relative = source.relative_to(source_dir)
            if target is None:
                report.skipped_platform.append(str(Path(home) / relative))
                continue
            destination = target / relative
            existing = destination.read_text(encoding='utf-8') if destination.exists() else None
            content = merge_text(relative.name, existing, source.read_text(encoding='utf-8'), report, declared)
            if content is None or existing == content:
                report.unchanged.append(str(destination))
                continue
            (report.created if existing is None else report.updated).append(str(destination))
            if dry_run:
                diff = difflib.unified_diff((existing or '').splitlines(), content.splitlines(),
                                            str(destination) if existing else '/dev/null', str(destination),
                                            lineterm='')
                print('\n'.join(diff), file=out)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding='utf-8')
            touched.append(destination)
    return report, touched


# Command line

def pull(serial):
    adb = ['adb'] + (['-s', serial] if serial else [])
    work = Path(tempfile.mkdtemp(prefix='selogger-'))
    try:
        subprocess.run(adb + ['shell', 'selogger', 'dump', '--out-dir', DEVICE_DUMP_DIR], check=True)
        subprocess.run(adb + ['pull', DEVICE_DUMP_DIR, str(work)], check=True,
                       stdout=subprocess.DEVNULL)
    except FileNotFoundError:
        raise Error('adb was not found')
    except subprocess.CalledProcessError as error:
        raise Error(f'{" ".join(error.cmd)} failed')
    return work / Path(DEVICE_DUMP_DIR).name


def find_checker(start):
    for directory in [start.resolve(), *start.resolve().parents]:
        if (directory / CHECKER).is_file():
            return directory / CHECKER
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--dump', type=Path, help='a dump pulled from the device')
    source.add_argument('--pull', action='store_true', help='run "selogger dump" over adb and pull it')
    parser.add_argument('--serial', help='adb serial for --pull')
    parser.add_argument('--sepolicy-dir', type=Path, required=True,
                        help='the vendor sepolicy directory of the device tree')
    parser.add_argument('--platform-dir', type=Path,
                        help='where the platform/ files of the dump go; skipped without it')
    parser.add_argument('--dry-run', action='store_true', help='show what would change and write nothing')
    parser.add_argument('--checker', type=Path,
                        help='check_sepolicy.py to run on the files written (default: the one in the tree)')
    parser.add_argument('--no-check', action='store_true', help='do not run the style check')
    args = parser.parse_args(argv)

    try:
        dump_root = args.dump if args.dump else pull(args.serial)
        if not (dump_root / 'REVIEW.md').is_file():
            raise Error(f'{dump_root} is not the output of "selogger dump"')
        if not args.sepolicy_dir.is_dir():
            raise Error(f'{args.sepolicy_dir} is not a directory')
        report, touched = expand(dump_root, args.sepolicy_dir, args.platform_dir, args.dry_run)
    except Error as error:
        print(f'selogger_expand: {error}', file=sys.stderr)
        return 1

    print(report.summary())
    print(f'Read {dump_root / "REVIEW.md"} for what needs a decision.')
    if args.dry_run or args.no_check or not touched:
        return 0

    checker = args.checker or find_checker(args.sepolicy_dir)
    if not checker:
        print('The style check was not found; run it by hand.', file=sys.stderr)
        return 0
    result = subprocess.run([sys.executable, str(checker)] + [str(path) for path in touched])
    return result.returncode


if __name__ == '__main__':
    sys.exit(main())
