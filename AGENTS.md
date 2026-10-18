# AGENTS.md - selogger

> Read this file in full before reading or changing anything in this
> directory. It holds the rules and facts that the code does not show.

selogger collects SELinux denials on the device, keeps them across
reboots in `/data/vendor/selogger`, and turns them into sepolicy
snippets for a device tree: `.te` rules (using the `te_macros`
macros where they fit) and label suggestions for the `*_contexts` files.
It is a userdebug/eng debugging tool and is shared by devices, so
nothing in it may be specific to one device.

See `hardware/mainline/common/AGENTS.md` and its `docs/` for the shared
code style, workflow and commit conventions that apply here, with the
deviations listed in "Conventions" below.

## Conventions

- Names never contain `lineage`/`lineageos`. Properties are
  `vendor.selogger.*`. The init service is `vendor.selogger`.
- Commit subject prefix is `selogger: ` (this is a standalone repository,
  not `mainline/common`). Subject, body and trailers otherwise follow
  `hardware/mainline/common/docs/COMMIT_CONVENTIONS.md`.
- Do not start Android builds, or run anything on a device or VM, without
  being told how (`docs/WORKFLOW.md`).

## Architecture

- `src/` outside `src/android/` is plain C++ with no Android services: it
  is built for the host and unit tested (`tests/`). Keep it that way.
  Anything that needs logd, netlink, init sockets or properties lives in
  `src/android/`.
- `Collector` is the only place that decides when to write or go idle. It
  never reads a clock or sleeps: callers pass monotonic seconds and
  obey the delay `Tick()` returns. The daemon therefore has no timers
  while idle. Do not add polling.
- Denials are read from logd's `logdr` socket directly, because
  `log/log_read.h` is not exported to vendor modules. The events buffer
  (tag 1003, `auditd`) is used rather than main: it holds the raw audit
  string and is not subject to chatty deduplication. logd strips `pid=`
  from those strings and appends `bug=`/`app=`.
- Treble limits what the command line (the adb shell, a core domain) may
  do to the vendor daemon: no `connectto` on its socket and no setting of
  vendor properties (both are neverallows). It also may not use the
  `read_logd()` macro in a vendor domain, since that adds `logcat_exec`.
  So the command line and the daemon talk through `command`/`reply` files
  in the state directory (setgid to the shell group), and the daemon
  waits on inotify. Do not go back to a socket or property without
  checking the neverallows (`m selinux_policy` with this sepolicy included).
- The audit rate limit is set through the kernel's audit netlink socket,
  as `system/logging/logd/auditctl.cpp` does. `persist.logd.audit.rate`
  is a `system_internal_prop`: vendor code (including vendor init rc
  files) cannot set it, so do not try to go through that property.
  Someone else changing the rate shows up in the audit stream as
  `type=1305 ... op=set audit_rate_limit=N`; the daemon reacts to it.
- The journal format is versioned by its first line (`#selogger-journal 1`).
  A change that older files cannot be read with needs a new version and a
  reader for the old one, because the file is the user's collected work.
  The `M` line holds what is not a tuple (the resume time, the kernel's
  drop count with its boot). Readers skip fields they do not know, so
  adding one does not need a new version.

- `selogger dump` is a pipeline: journal -> `RunLabelers` -> `GenerateRules`
  -> `BuildOutputFiles`. Labelers see only tuples whose target is a generic
  fallback type and answer with new types, `*_contexts` lines and
  *retargeted* copies of the denial, so rule generation and macro
  matching run on the labels that were proposed. They run in order (daemons
  first, since a daemon found in init's denials is a new domain), and each
  works on the result of the one before. Everything that asks the device
  goes through `DeviceInfo`; labelers must not read files themselves, so
  they stay testable with a fake.
- Output is split into `vendor/` and `platform/`. A rule or label belongs in
  `platform/` when vendor sepolicy cannot hold it (private platform domain,
  path outside the vendor partitions, non-vendor property). Do not drop
  such output; the maintainer needs to see it.
  Labels follow the domain that needs them: a private platform domain
  cannot name a vendor type, so what it needs is labeled in `platform/`.
  `genfscon` matches a prefix, so a numbered instance (`wakeup14`, `hwmon0`)
  is labeled at its directory. The `su` domain (the root shell) is left out.
- The macro table in `src/analyze/macros.cpp` mirrors
  `system/sepolicy/public/te_macros`. Only rules whose source is the first
  argument are matched; the rest are granted as a side effect. When a macro
  changes upstream, update the table (the permission sets come from
  `public/global_macros`). The matcher checks type attributes against the
  device's CIL, and a type nothing is known about has no attributes, so no
  macro that needs one matches.
- The `.te` file is processed by m4: no apostrophes in comments inside
  `userdebug_or_eng(...)` (they end the quote), and backquotes only as quotes.
- Everything `dump` writes must pass
  `device/mainline/common/build/tools/check_sepolicy.py`: sections in
  alphabetical order (so the sections of a domain file are Declarations,
  Extended permissions, Macros, Rules, Withheld), rules before macro
  calls and both case-insensitively sorted, tabs in `file_contexts` and
  `genfs_contexts`, directories first in `file_contexts`
  (`src/analyze/style.cpp`). Comment titles that are not sections must
  not look like one (use a full stop: "Generated by selogger.").
  To check: `SELOGGER_TEST_OUT=/tmp/out selogger_tests
  --gtest_filter='Pipeline*'` and run the checker on `/tmp/out`.
- `scripts/selogger_expand.py` mirrors the checker's ordering in Python
  (`sort_entries`, `parse_heading`); keep it in step with `style.cpp`.
  It must never remove or rewrite what a device tree already has, and must
  stay idempotent (a second run changes nothing).
- Unknown input never fails the dump: a missing CIL or contexts file
  leaves that information out, with a warning.
- Type names the labelers invent must not clash with the policy or each
  other (`LabelContext::FreshTypeName`).

## Reference paths

- logd: `system/logging/logd/` (`LogAudit.cpp` for what lands in the
  events buffer, `LogReader.cpp` for the reader protocol).
- sepolicy macros: `system/sepolicy/public/te_macros`,
  `public/global_macros` (permission sets).
- CIL and contexts files on a device: `/system/etc/selinux/plat_*`,
  `/vendor/etc/selinux/vendor_*` (and `system_ext`, `product`, `odm`);
  `plat_sepolicy_vers.txt` has the suffix of versioned (public) names.
- libselinux matching: `external/selinux/libselinux/src/label_backends_android.c`
  (services exact, properties by prefix).
- Kernel messages: `kernel/mainline/android-mainline`
  (`kernel/audit.c`, `security/selinux/avc.c`).
- Recent kernels print two spaces after `avc:`; the parser must accept any.

## Testing

- Host tests: `selogger_tests` (see README). They need no device.
- Host tool tests: `python3 -m unittest discover -s tools/selogger/tests`;
  they run the style checker over merged results when the tree has it.
- Policy check: include `tools/selogger/sepolicy/vendor` in a device's
  `BOARD_VENDOR_SEPOLICY_DIRS` temporarily and run `m selinux_policy`
  (also given by the maintainer). It compiles the policy and runs the
  neverallow checks. Revert the device change afterwards.
- `mmm tools/selogger` builds everything in the repository, host tests
  included; run `out/host/linux-x86/testcases/selogger_tests/x86_64/selogger_tests`.
- Not yet run on a device or VM: the policy compiles and passes the
  neverallow checks, but runtime denials for the daemon (and the dump) are
  still to be found. `selogger` collecting its own denials is a good test.
