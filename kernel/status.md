# kernel status

This directory contains a minimal x86_64 kernel intended to run monacc-built userland (Linux syscall ABI), initially under QEMU.

## Current state (as implemented)

- **Compiler**: monacc (self-hosted C compiler from this repo)
- **Assembler**: GNU as (for `.S` files only)
- Boot: Multiboot2 via GRUB ISO (BIOS + UEFI)
- Console: COM1 serial (QEMU `-serial stdio`)
- Privilege: ring 0 kernel + ring 3 user entry
- Syscall entry: x86_64 `syscall`/`sysretq` (Linux syscall ABI) with a dedicated kernel syscall stack; an `int 0x80` gate is also installed for debugging/legacy tests
- Exceptions: minimal handlers for #UD/#DF/#GP/#PF dump state to serial and halt
- Deterministic termination: `isa-debug-exit` on port `0xF4`

Process model (current bring-up design):

- **Single shared address space (identity mapping)**: virtual == physical
- **ET_EXEC userland** loads at fixed addresses (typically `0x400000`)
- **Multi-process without per-process page tables** is implemented by snapshot/restore:
	- user image region `[img_base, img_end)` copied to/from a per-process backup on each context switch
	- user stack region copied to/from a per-process backup on each context switch

This is a deliberate temporary design to get real userland running before introducing per-process page tables or CoW.

Filesystem / userland loading:

- Initramfs: Multiboot2 module containing an uncompressed CPIO `newc` archive
- VFS model: initramfs-backed, read-only file + directory layer
- Directory iteration: `getdents64` synthesizes Linux `dirent64` records from CPIO path prefixes

Known policy (temporary):

- Legacy PIC is remapped to 0x20-0x2F and all IRQ lines are masked by default.
	Ring 3 can run with IF=1 safely in this configuration; later work can unmask specific IRQs.

### Phases completed

- Phase 0: boot to long mode + serial banner
- Phase 1: ring 3 entry + `exit(60)`
- Phase 2: `read(0)` + `write(1/2)` over serial + user test prints then exits
- Phase 3: `mmap`/`munmap` with physical page allocator (PMM)
- Phase 4: initramfs (CPIO `newc`) file + directory syscalls sufficient for `cat`, `tail`, `ls`
- Phase 5: exec from initramfs via `execve()` (e.g. `kinit` -> `/bin/ls -R /`)
- Phase 6: `fork()` + `wait4()` (enough for real shell usage)
- Phase 7: `pipe2()` + `dup2()` (pipelines work)

Validated tools / behaviors:

- `cat`/`tail` from initramfs
- `ls /`, `ls -l /`, and `ls -R /` complete without faults (with user IF forced off)
- `/bin/sh -c "cd /bin; /bin/pwd; /bin/echo hello | /bin/cat"` completes and prints expected output
- Interactive `bin/sh` works as PID 1 (serial prompt + basic line editing)
- `cat hello.txt` works from the initramfs
- `mandelbrot` runs successfully

Build artifacts (ISO/initramfs):

- The ISO produced by `grub-mkrescue` is expected to look “large” relative to the kernel/initramfs because it embeds a full GRUB runtime (hundreds of modules) plus BIOS+UEFI El Torito boot images.
- The kernel ISO build defaults to using `../release/monacc-dev-initramfs.cpio` (if present) as the Multiboot2 initramfs module.

Key implementation detail for correctness under identity mapping:

- **Fixed virtual user stack region**: all processes use the same active stack virtual range
	- `USER_STACK_BASE..USER_STACK_TOP` is reserved in the PMM so it will never be handed out
	- each process has a stack backup buffer; the scheduler copies the active stack in/out on switches
	- `fork()` clones the parent stack backup (not the live stack at a different address)

### monacc compatibility status

The kernel now builds with monacc instead of gcc/clang. Several workarounds were required:

1. **Keep privileged/rare instructions out of monacc-compiled C**: monacc's internal assembler is intentionally small and may reject instructions like `cli`, `hlt`, and `mov %cr2, ...`. Workaround: implement low-level CPU helpers in GNU-as `.S` stubs (see `arch/lowlevel.S`) and call them from C.

2. **Inline-asm operand modifiers**: `%b/%w/%k/%q` are now supported in monacc; no kernel workarounds currently needed.

3. **`sizeof(array)` correctness**: fixed in monacc; the kernel can rely on `sizeof(array)`.

4. **Memory operand `"m"` constraint issues with `lgdt`/`lidt`**: Packed structs used as memory operands don't work reliably. Workaround: use `.S` stubs for `lgdt`/`lidt` so C just passes a pointer.

5. **`__builtin_unreachable()`**: fixed in monacc; use where appropriate.

6. **`extern unsigned char sym[]` linkage**: fixed in monacc; the kernel can use normal linker-symbol array patterns.

7. **Function-scope `static` storage**: fixed in monacc.

8. **Packed struct `sizeof`**: fixed in monacc.

9. **Packed struct member offsets**: fixed in monacc.

10. **Aggregate assignment/copy**: fixed in monacc; kernel can use idiomatic `{0}` initialization.

## How to build

```bash
# Build kernel ISO (from kernel/ directory)
cd kernel
make clean && make iso

# Run (implies iso rebuild if needed)
make run-bios-serial

# Note: if ../release/monacc-dev-initramfs.cpio exists, it will be included
# by default in the ISO as a Multiboot2 module.

# Override (or disable) the initramfs module explicitly:
make INITRAMFS=../build/initramfs/sysbox.cpio iso
make INITRAMFS= run-bios-serial

# From the repo root instead:
cd ..
make -C kernel iso
```

The Makefile uses monacc (../bin/monacc) for C files and GNU as for assembly files.

## How to run

- Main run: `make run-serial`
- Debug logging (exceptions etc): `make run-bios-serial-log` (writes `build/qemu.log`)

You can also run QEMU manually (equivalent to `make run-bios-serial`):

```bash
cd kernel
qemu-system-x86_64 -cdrom build/kernel.iso -display none -monitor none \
	-serial stdio -no-reboot \
	-device isa-debug-exit,iobase=0xf4,iosize=0x04
```

Expected serial output includes:
- `monacc kernel`
- `Entering userland...`
- user message (Phase 2 test)
- `Process exited with code 0`

## Key pitfalls to remember

### monacc-specific issues

- **lgdt/lidt memory operands**: Build the descriptor table pointer as a byte array and use register-indirect addressing.

### General kernel issues

- BIOS vs UEFI: if SeaBIOS won’t boot the ISO, ensure your host has BIOS GRUB modules installed (Debian/Ubuntu: `grub-pc-bin`).
- Multiboot2 section flags: the Multiboot2 header section must be allocatable (`"a"`) or the ELF LOAD segment may start at `VirtAddr=0`, causing subtle catastrophic crashes.
- Accidental SSE/x87 in early kernel: the compiler may emit `xmm` instructions before you’ve enabled FPU/SSE, leading to #UD and triple faults. Either initialize FPU/SSE early or keep early CFLAGS disabling them.
- Embedded user blobs: ensure `userprog_end` is placed after all bytes (including strings) so the kernel copies code+data.

### Identity-mapped multi-process hazards

- **Do not relocate the user stack VA per process**: under identity mapping, pointers into stack memory are plain virtual addresses.
	If a child gets a different stack base address, any pointers-into-stack become invalid and real programs (notably `/bin/sh`)
	will quickly crash. Use a fixed stack VA and snapshot/restore semantics.

### Interrupts (current bring-up constraint)

- If interrupts are enabled in ring3 before remapping/masking the legacy PIC (or switching to APIC),
  hardware IRQs can arrive on vectors overlapping CPU exceptions (0x08-0x0f), causing cascaded faults.

## Suggested next steps

- Proper IRQ infrastructure: PIC remap+mask (or APIC) + IRQ handlers, then optionally re-enable ring3 interrupts
- Reduce syscall debug noise (gate or rate-limit syscall logging)
- Phase 6+: fork/wait + scheduler + pipes to support `sh` pipelines

## Kernel size notes (future work)

The kernel is currently under the <100KB goal. If we want to shrink it further later, without making debugging painful:

- **Strip the ISO payload**: keep an unstripped `build/kernel.elf` for GDB, but copy a stripped ELF into the ISO (dropping `.symtab/.strtab`).
- **Make bring-up blobs optional**: exclude embedded user test blobs (e.g. echo/mmap) in “release” builds once initramfs execution is reliable.
- **Compile out verbose logs**: gate chatty `serial_write("[k] ...")` strings behind a `KDEBUG`/`KLOG` macro.
- **Enable better dead-code GC**: split large translation units (notably `main.c`) into smaller `.c` files so unused subsystems can be linked out.
