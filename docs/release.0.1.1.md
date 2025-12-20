# Release 0.1.1 — QEMU test-drive gaps

This note tracks items discovered while booting the monacc kernel in QEMU and using the monacc userland interactively.

Goal for 0.1.1: improve basic usability in the minimal VM without expanding scope beyond the syscall-only toolchain.

## Tooling + usability gaps

The 0.1.1 focus is “make the VM pleasant to debug and iterate in”.

Given the constraints in [docs/spec.md](spec.md):
- syscall-only tools (no libc)
- predictable behavior and exit codes (0/1/2)
- small flag subsets, stable-ish text output

…the most leverage tends to come from a small set of inspection + packaging tools that can be composed in pipelines.

High-value additions (and the reason they matter in the QEMU test-drive loop):
- **ELF inspection**: `readelf` + `objdump` let you debug the compiler/linker/kernel loader boundary from inside the VM.
- **Byte-level inspection**: `xxd` is a “glue” tool to validate file formats and offsets in scripts.
- **Initramfs/workspace packaging**: `cpio`/`uncpio` (newc) enables round-trip creation/list/extract workflows without leaving the monacc tool universe.

Next logical 0.1.1-sized tool/features (useful, but keep them minimal):
- **Kernel observability**: make `dmesg` useful under the monacc kernel (ring buffer or a `/proc/kmsg`-style interface), so tool failures can be correlated with kernel behavior.
- **Process visibility**: improve `ps` output (PPID/state, or a stable “tree” mode) so interactive debugging of pipelines/forks is less guessy.
- **CLI contract hardening**: add regression tests that lock in “usage error → exit 2” for the developer tools (`readelf/objdump/xxd/cpio`) to prevent accidental CLI drift.
- **Init ergonomics**: make `/init` set a helpful default environment (PATH, prompt, maybe `mount`/`proc` bringup depending on kernel mode) and print one short “how to use this VM” banner.

## Networking (monacc kernel)

This section used to describe “boot initramfs on a Linux kernel and use Linux networking”.

Now that we have our own kernel, networking needs to be re-thought end-to-end:

Key design questions (pick an approach before writing tools):
- **API surface**: do we want Linux-like `socket()` syscalls (so existing net tools can run), or a smaller custom net API?
- **Where the stack lives**: full in-kernel TCP/IP, or a **host-proxy** transport (e.g. a simple “net proxy” over a virtio/serial channel) as a stepping stone?
- **Device**: which emulated NIC do we target first (e1000 vs virtio-net), and do we need IRQ-driven RX yet?
- **Configuration**: static IP first vs DHCP; IPv4 vs IPv6 as the first supported path.

Suggested minimum milestone (if we want network access soon):
- Decide the approach (socket-compat vs proxy).
- Get **one** reliable connectivity demo working in QEMU (even if it’s only outbound TCP/UDP via a proxy).

## Non-goals for 0.1.1

- Full POSIX shell compatibility
- Full GNU coreutils parity
- Complex networking stack configuration / module management

## Checklist

- [x] Add minimal developer inspection tools (`readelf`, `objdump`, `xxd`) and cover them with regression tests
- [x] Add initramfs/workspace packaging tools (`cpio`, `uncpio`) and cover round-trip + safety behavior with tests
- [ ] Make kernel logging observable in userland (so `dmesg` works under the monacc kernel)
- [ ] Improve process visibility for debugging (extend `ps`, or add a tiny `pstree`-style view)
- [ ] Decide and document the networking approach for the monacc kernel (socket-compat vs host-proxy), then implement one minimal connectivity demo in QEMU
