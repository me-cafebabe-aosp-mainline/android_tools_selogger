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

## Reference paths

- logd: `system/logging/logd/` (`LogAudit.cpp` for what lands in the
  events buffer, `LogReader.cpp` for the reader protocol).
- sepolicy macros: `system/sepolicy/public/te_macros`,
  `public/global_macros` (permission sets).
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
