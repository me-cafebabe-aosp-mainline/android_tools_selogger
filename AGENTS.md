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
- The audit rate limit is set through the kernel's audit netlink socket,
  as `system/logging/logd/auditctl.cpp` does. `persist.logd.audit.rate`
  is a `system_internal_prop`: vendor code (including vendor init rc
  files) cannot set it, so do not try to go through that property.
  Someone else changing the rate shows up in the audit stream as
  `type=1305 ... op=set audit_rate_limit=N`; the daemon reacts to it.
- The journal format is versioned by its first line (`#selogger-journal 1`).
  A change that older files cannot be read with needs a new version and a
  reader for the old one, because the file is the user's collected work.

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
- The macro table in `src/analyze/macros.cpp` mirrors
  `system/sepolicy/public/te_macros`. Only rules whose source is the first
  argument are matched; the rest are granted as a side effect. When a macro
  changes upstream, update the table (the permission sets come from
  `public/global_macros`). The matcher checks type attributes against the
  device's CIL, and a type nothing is known about has no attributes, so no
  macro that needs one matches.
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
- Kernel messages: `/android/common/kernel/mainline/android-mainline`
  (`kernel/audit.c`, `security/selinux/avc.c`).
- Recent kernels print two spaces after `avc:`; the parser must accept any.

## Testing

- Host tests: `selogger_tests` (see README). They need no device.
- Compile test of the service: `cd /android/LineageOS/24 && source
  build/envsetup.sh && breakfast mi8953_a && m selogger` (given by the
  maintainer; use bash, it fails when sourced from zsh in a subshell).
- Not yet run on a device or VM: the sepolicy in `sepolicy/vendor/` has not
  been compiled or exercised. Expect to iterate on it.
