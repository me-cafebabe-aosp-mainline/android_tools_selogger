# selogger

selogger collects SELinux denials on a device and keeps them across
reboots, so that you can turn them into sepolicy for your device tree
later. It is meant for userdebug/eng bring-up, not for user builds.

What it does:

- A small daemon reads the denials from logd and stores each *kind* of
  denial once, with counters, in `/data/vendor/selogger`.
- It raises the kernel's audit rate limit while you are still finding
  denials, so fewer of them are dropped, and puts it back afterwards.
- (planned in the next commits) `selogger dump` writes `.te` files that use
  the `te_macros` macros, and suggests labels for the `*_contexts` files.

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

3. Build, flash, and use the device. The service starts by itself.

## Using it

```sh
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

## How it works

```
kernel audit --> logd --events buffer--> selogger --> /data/vendor/selogger/
                                           ^   |            denials.journal
                              audit rate --+   +-- control socket (CLI)
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
- The daemon has no timers while nothing happens: it blocks on logd, and
  on a condition variable until work is due.

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
| `src/analyze/` | Turning collected denials into policy (see below). |
| `src/android/` | Parts that need Android: logd socket, audit netlink, control socket, daemon. |
| `selogger.rc`, `config/` | Init service and default configuration. |
| `sepolicy/vendor/` | Policy of the service itself. |
| `tests/` | Host tests (`selogger_tests`). |

## Development

The code that does not touch Android (everything outside `src/android/`)
is built for the host as `libselogger_core`, and `selogger_tests` runs its
tests:

```sh
m selogger_tests && out/host/linux-x86/nativetest64/selogger_tests/selogger_tests
```
