# kernel status

This directory contains a minimal x86_64 kernel intended to run monacc-built userland (Linux syscall ABI), initially under QEMU.

## Current state (as implemented)

- Boot: Multiboot2 via GRUB ISO (BIOS + UEFI)
- Console: COM1 serial (QEMU `-serial stdio`)
- Privilege: ring 0 kernel + ring 3 user entry
- Syscall entry: `int 0x80` IDT gate (DPL=3) with TSS `rsp0` stack switching
- Deterministic termination: `isa-debug-exit` on port `0xF4`

### Phases completed

- Phase 0: boot to long mode + serial banner
- Phase 1: ring 3 entry + `exit(60)`
- Phase 2: `read(0)` + `write(1/2)` over serial + user test prints then exits

## How to run

- Main run: `make run-serial`
- Debug logging (exceptions etc): `make run-bios-serial-log` (writes `build/qemu.log`)

Expected serial output includes:
- `monacc kernel`
- `Entering userland...`
- user message (Phase 2 test)
- `Process exited with code 42`

## Key pitfalls to remember

- BIOS vs UEFI: if SeaBIOS won’t boot the ISO, ensure your host has BIOS GRUB modules installed (Debian/Ubuntu: `grub-pc-bin`).
- Multiboot2 section flags: the Multiboot2 header section must be allocatable (`"a"`) or the ELF LOAD segment may start at `VirtAddr=0`, causing subtle catastrophic crashes.
- Accidental SSE/x87 in early kernel: the compiler may emit `xmm` instructions before you’ve enabled FPU/SSE, leading to #UD and triple faults. Either initialize FPU/SSE early or keep early CFLAGS disabling them.
- Embedded user blobs: ensure `userprog_end` is placed after all bytes (including strings) so the kernel copies code+data.

## Suggested next steps

- Add minimal exception handlers (#PF/#GP/#DF) that print diagnostics to serial (vector, error code, RIP/CS/RSP/SS, CR2 for #PF).
- Phase 3: implement `mmap` (anonymous private) with a simple page allocator + per-process page tables.
- Start a small “syscall coverage” checklist mapping monacc tools to required syscalls.
