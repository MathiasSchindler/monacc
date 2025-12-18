# Release 0.1.1 — QEMU test-drive gaps

This note tracks items discovered while booting the initramfs in QEMU (Linux x86_64) and using the monacc userland interactively.

Goal for 0.1.1: improve basic usability in the minimal VM without expanding scope beyond the syscall-only toolchain.

## Missing tools

### `tar`
Why:
- Moving files in/out of the VM or between host/guest is awkward without a basic archiver.

Acceptance:
- `tar cf out.tar dir/` and `tar xf out.tar` work.
- Supports regular files + directories, preserves file modes (at least executable bit).
- Optional (nice): `tar czf`/`tar xzf` when paired with gzip.

### `gzip` / `gunzip`
Why:
- Needed for handling `.gz` artifacts and pairing with `tar` for portable bundles.

Acceptance:
- `gzip <in >out.gz` and `gunzip <in.gz >out` work.
- File-based `gzip file` / `gunzip file.gz` is optional but preferred.

### `dmesg`
Why:
- Debugging boot/device/network issues in the VM needs quick access to the kernel ring buffer.

Acceptance:
- Prints kernel log buffer.
- Optional flags later; for 0.1.1 a minimal default output is fine.

## Shell usability tweaks

### Prompt formatting (show current directory)
Why:
- In an interactive VM, it’s easy to get lost without context.

Acceptance:
- Default interactive prompt includes at least current directory, e.g. `PWD $ `.
- Keep it simple (no colors required).

Notes / approach:
- Implement minimal `$PWD` tracking in `sh` (update on `cd`).
- Either add `PS1` support or hardcode a reasonable default for interactive sessions.

## `ls` usability tweaks

### Human-readable timestamps
Why:
- Debugging and basic file inspection in the VM benefits from readable times.

Acceptance:
- When showing a long listing (or a new flag), timestamps are human readable.
- Example target behavior: `ls -la` prints `YYYY-MM-DD HH:MM` (exact format can be simple and consistent).

Notes / approach:
- Add a minimal time formatting helper (UTC is acceptable).
- No need for locale handling.

## Networking in QEMU

### Guest connectivity
Why:
- The userland includes network tools, but in the initramfs VM there is no connectivity unless devices and IP configuration are present.

Acceptance:
- VM can reach an external IP/host using existing tools (e.g. `ping6` where applicable).
- At least one documented QEMU invocation provides working networking.

Minimum plan:
- Document a known-good QEMU config (e.g. user-mode networking + an emulated NIC):
  - `-netdev user,id=n0 -device e1000,netdev=n0`
- Add one of:
  1) a tiny DHCP client tool (preferred), or
  2) a minimal static IP configuration tool (even more minimal), or
  3) teach `init` to configure a default setup when kernel cmdline provides IP parameters.

Notes:
- The kernel must include the relevant NIC driver (e1000/virtio-net) built-in, otherwise modules would be needed (not present in initramfs).

## Non-goals for 0.1.1

- Full POSIX shell compatibility
- Full GNU coreutils parity
- Complex networking stack configuration / module management

## Checklist

- [x] Add `tools/tar.c`
- [x] Add `tools/gzip.c` and `tools/gunzip.c` (or a single multi-call binary)
- [x] Add `tools/dmesg.c`
- [x] Improve interactive prompt in `tools/sh.c`
- [x] Add human-readable time formatting in `tools/ls.c`
- [ ] Provide documented QEMU command line that yields working networking (and add the minimal userland support needed to configure it)
