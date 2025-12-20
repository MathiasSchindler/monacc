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

## Developer tools (low-hanging fruit)

### Minimal ELF inspector (`readelf`-like)

Why:
- During bring-up and debugging we frequently want quick answers to “what is this binary?” (entry point, load segments, symbols) without needing external host tooling.

Minimal useful features:
- `-h`: print ELF header (class, endianness, machine, entry point).
- `-l`: print program headers (PT_LOAD ranges, flags) so loader issues are easy to spot.
- `-S`: print section headers (names, addresses, sizes) for quick sanity checks.
- `-s`: print symbol table (at least name/value/size/binding/type) if present.

Non-goals:
- Disassembly or relocation decoding (can be added later if needed).

### Minimal object inspector (`objdump`-like)

Why:
- Sometimes the useful view is “object-centric” (sections + symbols) rather than ELF-loader-centric.
- Helps debug internal-linker/assembler issues without requiring host `objdump`.

Minimal useful features:
- `-h`: print section table summary (name, size, vma/lma, flags) for ET_REL and ET_EXEC.
- `-t`: print symbols (name, value, size, section index) if present.
- `-p` (optional): show file format + machine + entry point for ET_EXEC.

Non-goals:
- Full disassembly (`-d`) or relocation decoding.

### Hex dump (`xxd`-like)

Why:
- Faster than `hexdump` for eyeballing binary structures (CPIO headers, ELF headers, TLS records, etc.).

Minimal useful features:
- Default: canonical `xxd`-style output with offsets + hex bytes + ASCII.
- `-g1` (or default 1-byte grouping): show byte granularity.
- `-l N`: limit output length.
- `-s OFF`: start offset.

Non-goals:
- Reverse mode (`-r`) can wait.

### Initramfs helpers (`cpio` / `uncpio`)

Why:
- The initramfs format is CPIO newc; being able to list/extract/create archives inside the VM reduces friction.

Minimal useful features:
- `cpio -t < archive.cpio`: list file names.
- `cpio -i < archive.cpio`: extract to current directory (regular files + dirs).
- `cpio -o > archive.cpio`: create a newc archive from a file list on stdin.

Non-goals:
- Full permission/mtime preservation, devices, symlinks, and all GNU cpio flags.

## Checklist

- [ ] Decide and document the networking approach for the monacc kernel (socket-compat vs host-proxy), and implement the first working connectivity demo in QEMU
- [ ] Add a minimal ELF inspector tool (`readelf`-like: `-h/-l/-S/-s`)
- [ ] Add a minimal object inspector tool (`objdump`-like: `-h/-t`)
- [ ] Add an `xxd`-like hex dump tool (`-l/-s`, byte grouping)
- [ ] Add minimal `cpio` / `uncpio` tools for newc (list/extract/create)
