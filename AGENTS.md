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
