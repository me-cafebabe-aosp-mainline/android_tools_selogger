# selogger

selogger collects SELinux denials on a device and keeps them across
reboots, so that you can turn them into sepolicy for your device tree
later. It is meant for userdebug/eng bring-up, not for user builds.

What it does:

- A small daemon reads the denials from logd and stores each *kind* of
  denial once, with counters, in `/data/vendor/selogger`.
- It raises the kernel's audit rate limit while you are still finding
  denials, so fewer of them are dropped, and puts it back afterwards.
- `selogger dump` turns what was collected into `.te` files that use the
  `te_macros` macros, and suggests labels for the `*_contexts` files.

It runs in the vendor partition and does not depend on the device.

## Adding it to a device

1. Build it into debug builds, in `device.mk`:

   ```make
   PRODUCT_PACKAGES_DEBUG += selogger
   ```

2. Let the device sepolicy include the rules of the tool, in
   `BoardConfig.mk`:

   ```make
   BOARD_VENDOR_SEPOLICY_DIRS += tools/selogger/sepolicy/vendor
   ```

   The rules are wrapped in `userdebug_or_eng()`; only the type
   declarations are present in user builds.

3. Build, flash, and use the device. The service starts by itself. The
   command line works from a normal (unrooted) adb shell.

## Using it

```sh
adb shell selogger dump          # write sepolicy for what was collected
adb shell selogger status        # what has been collected
adb shell selogger flush         # write the counters now
adb shell selogger collect off   # restore the kernel's audit rate limit
adb shell selogger collect on    # raise it again
adb shell selogger clear         # forget everything
```

`status` also shows `kernel_lost`, the number of denials the kernel
dropped because of its rate limit. If it is not zero, exercise the device
again after raising `collect_audit_rate`, or put the domain you are
working on in permissive mode while you collect.

## Getting policy out of it

```sh
adb shell selogger dump          # writes /data/local/tmp/selogger-dump
adb pull /data/local/tmp/selogger-dump
```

(`--out-dir DIR` writes elsewhere, `--stdout` prints everything,
`--raw` prints the collected denials as they are.)

The result:

| File | What to do with it |
|------|--------------------|
| `REVIEW.md` | Read first: what needs a decision, and the most frequent denials. |
| `vendor/<domain>.te` | Copy into the device's sepolicy. |
| `vendor/file.te`, `property.te`, `service.te` | Declarations of the types the labels below use. |
| `vendor/file_contexts`, `genfs_contexts`, `property_contexts`, `service_contexts`, `hwservice_contexts`, `vndservice_contexts` | Lines to add to the files of the same name. |
| `platform/...` | The same for domains and labels that vendor sepolicy cannot hold; they belong to the platform's sepolicy. |

A `<domain>.te` file has these sections:

- **Declarations**: new types and domains, and macros that set up a HAL.
- **Macros**: `te_macros` macros that stand in for denials, such as
  `get_prop()`, `set_prop()`, `unix_socket_connect()`, `binder_call()`,
  `read_logd()`, `add_service()` and `r_dir_file()`. A macro grants a bit
  more than was denied; that is its purpose.
- **Rules**: the denials that no macro explains, as `allow` lines.
- **Extended permissions**: `allowxperm` lines for ioctl commands.
- **Withheld**: rules that were not written, as comments, because they
  would not compile or should not be granted: a target that is unlabeled,
  a private platform type (Treble), ...

The rules are a starting point, not a verdict. Denials are as often a
sign of a missing label or a bug as of a missing rule, and the review
file says where it suspects that.

### Putting the result into the device tree

`scripts/selogger_expand.py` does that on the host. It takes the dump (or
pulls it over adb) and merges it into the sepolicy directory of the
device:

```sh
tools/selogger/scripts/selogger_expand.py --pull \
    --sepolicy-dir device/foo/bar/sepolicy/vendor
```

- New domains and contexts files are created; in files that exist, the
  new rules and entries go into the section they belong to, or a new
  section at the place where its title sorts, in the order
  `device/mainline/common/build/tools/check_sepolicy.py` expects.
  Nothing already there is removed or changed; only the permissions of an
  `allow` rule that is there are extended.
- Entries that are already present are left alone, so the tool can run
  again after the next round of collecting. A different label for a name
  that has one is reported as a conflict and not changed. A type that is
  declared in another file of the directory is not declared again.
- `--dry-run` shows the changes as a diff and writes nothing. `--dump DIR`
  uses a dump you pulled yourself, and `--serial` selects the device.
- `platform/` files of the dump are written to `--platform-dir` if you
  give one, and listed otherwise.
- The style check runs on the files that were written; `--no-check` skips
  it. It finds the checker in the tree, or use `--checker`.

Read `REVIEW.md` before building: the tool puts the rules in, it does not
decide whether they are right.

The files of a dump already follow the style of that checker, so a
device tree that does not use it still gets tidy files.

### Labels

Where the target of a denial is a fallback type (`default_prop`,
`default_android_service`, `vendor_file`, `device`, `sysfs`, `unlabeled`, ...),
allowing it would grant access to everything with that label. selogger
proposes a label instead, from what the denial says about the object:

| Object | Proposal |
|--------|----------|
| Property (`property=`) | `vendor_<name>_prop`, a `property_contexts` line |
| Service (`name=`) | `<name>_service`, a `service_contexts` line (`vndservice_contexts` for vndservicemanager); a HAL server in a `hal_foo_server` attribute gets `hal_attribute_service()` |
| HIDL interface (`interface=`) | `<name>_hwservice`, a `hwservice_contexts` line |
| File, directory, device node, socket (`path=`) | `<name>_exec`, `_data_file`, `_device`, `_socket` or `_file`, a `file_contexts` line; three or more siblings become one entry for the directory |
| sysfs, proc, debugfs, tracefs, configfs node | `vendor_<fs>_<name>`, a `genfscon` line for the real path (symbolic links resolved, existing `genfscon` checked) |
| Daemon that runs in `init`'s domain | a domain, an exec type, `init_daemon_domain()`, and the `file_contexts` line of the binary the process name leads to |

When the log gives an inode but no path, selogger looks for it on the
file system (with a limit on time and entries). Objects that are
per-process (`/proc/<pid>`) or per-app are left to the platform.

Some situations only get a note, since the answer is a decision: the
object is already labeled in `file_contexts` (relabel it, or fix the
process that creates it), a process creates files in a directory with a
fallback label (use `file_type_auto_trans()`), a read of a property that
is one of many with the same fallback label.

## How it works

```
kernel audit --> logd --events buffer--> selogger --> /data/vendor/selogger/
                                           ^   |            denials.journal
                              audit rate --+   +-- command/reply files (CLI)
```

- Denials are read from logd's reader socket (the `events` buffer, tag
  `auditd`). logd keeps no more than its buffer size, so selogger asks for
  everything logd still has when it starts, and for everything newer than
  the last entry it saw after that.
- A denial is reduced to *(source type, target type, class)*. For each of
  those the daemon keeps the union of the denied permissions and ioctl
  commands, counters, and a few identifying details (paths, property and
  service names, process names) that the label suggestions use.
- The journal is a text file: one line per tuple, a newer line replaces an
  older one. A new kind of denial is written after `flush_delay_s`;
  counter-only changes only every `count_flush_interval_s`. When the file
  passes `journal_max_bytes` it is rewritten.
- The daemon has no timers while nothing happens: it blocks on logd, on a
  condition variable until work is due, and on an inotify watch for
  commands.
- The command line cannot use a socket or a property to reach the daemon:
  Treble forbids a core domain such as the adb shell from connecting to
  a vendor socket or setting a vendor property. It drops a `command` file
  into the state directory and waits for the daemon's `reply` file.

### The audit rate limit

The kernel drops audit messages beyond its rate limit. logd's `auditctl`
sets it to 5 per second at the end of boot (`persist.logd.audit.rate`),
which is too low for collecting. That property belongs to the system
partition, so selogger sets the kernel limit itself (it holds
`CAP_AUDIT_CONTROL`, like `auditctl`). When logd's `auditctl` sets it back
at the end of boot, selogger sees the change in the audit stream and sets
it again, at most every 30 seconds.

After `idle_timeout_s` without a new kind of denial the limit goes back to
`idle_audit_rate`. The denials keep being collected at that rate. On a
stop of the service the limit is restored as well.

## Configuration

`/vendor/etc/selogger.conf` (from `config/selogger.conf`) has `key=value`
lines; all keys are optional.

| Key | Default | Meaning |
|-----|---------|---------|
| `state_dir` | `/data/vendor/selogger` | Where the journal lives. |
| `max_tuples` | 20000 | Bound on kept tuples; the oldest tenth goes when full. |
| `max_hints` | 16 | Bound on identifying details per kind and tuple. |
| `journal_max_bytes` | 1048576 | Size at which the journal is rewritten. |
| `flush_delay_s` | 5 | Delay before a new kind of denial is written. |
| `count_flush_interval_s` | 3600 | Interval for writing counters of known denials. |
| `collect_audit_rate` | 100 | Kernel audit rate (per second, 0 = unlimited) while collecting. |
| `idle_audit_rate` | 5 | Kernel audit rate when idle and after stopping. |
| `idle_timeout_s` | 600 | Seconds without a new tuple before going idle; 0 = never. |
| `start_collecting` | true | Raise the rate limit when the service starts. |
| `watch_audit_lost` | true | Read the kernel log for the kernel's dropped-message counter. |

Properties: `vendor.selogger.state` is `collecting`, `idle` or `stopped`.

## Source layout

| Path | Contents |
|------|----------|
| `src/avc.*` | Parser for `avc: denied` messages. |
| `src/tuple.*`, `src/journal.*` | The aggregated denials and their file. |
| `src/collector.*` | Flush and idle decisions, without clock or threads. |
| `src/config.*`, `src/events.*` | Configuration file and logd event decoding. |
| `src/analyze/` | The device's policy (`policy_db`), `te_macros` matching (`macros`), rule generation and the output files. |
| `src/label/` | The labelers and the `*_contexts` parsers. |
| `src/android/` | Parts that need Android: logd socket, audit netlink, command files, daemon, and the device-facing side of `dump`. |
| `scripts/selogger_expand.py` | Host tool: merges a dump into a device tree. |
| `selogger.rc`, `config/` | Init service and default configuration. |
| `sepolicy/vendor/` | Policy of the service itself. |
| `tests/` | Host tests: `selogger_tests` (C++), `test_selogger_expand.py`. |

## Limits

- The kernel drops denials beyond its rate limit and in enforcing mode a
  process usually stops at the first denial, so one run does not find
  everything. Collect, apply, rebuild, repeat; `permissive <domain>;` in
  the policy of the domain you work on shows all of its denials at once.
- `dontaudit` rules hide denials. Build the policy without them (for
  example `secilc --disable-dontaudit`) in a collection build if you
  suspect it.
- Only the first 16 distinct paths, names and so on of a denial are kept.
  The labels cover those; run again after applying them.
- The generated rules do not know the `neverallow` rules of the platform.
  Build the policy; the build tells.
- The macro matcher knows 15 macros of `public/te_macros`
  (`src/analyze/macros.cpp`). Others are written out as plain rules.

## Development

`mmm tools/selogger` builds the service, the host library and the tests.
The sepolicy can be checked by including it in a device temporarily and
building `m selinux_policy`, which also runs the neverallow checks.

The code that does not touch Android (everything outside `src/android/`)
is built for the host as `libselogger_core`, and `selogger_tests` runs its
tests:

```sh
mmm tools/selogger
out/host/linux-x86/testcases/selogger_tests/x86_64/selogger_tests
python3 -m unittest discover -s tools/selogger/tests    # the host tool
```
