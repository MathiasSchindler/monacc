# Release 0.1.1 — QEMU test-drive gaps

This note tracks items discovered while booting the monacc kernel in QEMU and using the monacc userland interactively.

Goal for 0.1.1: improve basic usability in the minimal VM without expanding scope beyond the syscall-only toolchain.

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

- [ ] Decide and document the networking approach for the monacc kernel (socket-compat vs host-proxy), and implement the first working connectivity demo in QEMU
