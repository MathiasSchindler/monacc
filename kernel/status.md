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

Validated tools / behaviors:

- `cat`/`tail` from initramfs
- `ls /`, `ls -l /`, and `ls -R /` complete without faults (with user IF forced off)

### monacc compatibility status

The kernel now builds with monacc instead of gcc/clang. Several workarounds were required:

1. **Keep privileged/rare instructions out of monacc-compiled C**: monacc's internal assembler is intentionally small and may reject instructions like `cli`, `hlt`, and `mov %cr2, ...`. Workaround: implement low-level CPU helpers in GNU-as `.S` stubs (see `arch/lowlevel.S`) and call them from C.

2. **No `%w` / `%b` operand modifiers in inline asm**: monacc doesn't support sized register operand modifiers like `%w0` (for 16-bit) or `%b0` (for 8-bit). Workaround: avoid inline asm in C where possible; otherwise use separate `__asm__ volatile` statements with full registers, or cast to appropriately-sized types.

3. **`sizeof(array)` returns element size, not array size**: This is a monacc bug. `sizeof(gdt)` for `uint64_t gdt[7]` returns 8 instead of 56. Workaround: hardcode sizes where needed (e.g., `7 * 8 - 1` for GDT limit).

4. **Memory operand `"m"` constraint issues with `lgdt`/`lidt`**: Packed structs used as memory operands don't work reliably. Workaround: use `.S` stubs for `lgdt`/`lidt` so C just passes a pointer.

5. **No `__builtin_unreachable()`**: monacc doesn't have this builtin. Workaround: use an infinite halt loop (e.g. `halt_forever()`) instead.

6. **`extern` array declarations create local BSS symbols**: When declaring `extern unsigned char userprog_start[]`, monacc generates a local BSS symbol instead of a proper external reference. Workaround: declare as function pointer `void userprog_start_func(void)` and cast: `(uint64_t)userprog_start_func`.

7. **`static` local arrays placed on stack, not BSS**: Static local arrays like `static uint8_t kstack0[16384]` are allocated on the function stack instead of BSS. Workaround: move to file scope.

8. **`sizeof(packed struct)` returns wrong value**: For packed structs, sizeof returns an incorrect (larger) value. TSS64 should be 104 bytes but monacc returns 112. Workaround: hardcode struct sizes.

9. **`__attribute__((packed))` not honored for struct layout**: Struct member offsets are aligned to natural boundaries regardless of packed attribute. TSS `rsp0` goes to offset 8 instead of 4. Workaround: use raw byte-level access with explicit offsets.

10. **Compound literal struct assignment only copies 8 bytes**: `tss = (struct tss64){0}` only zeros 8 bytes, not the full struct. Workaround: use explicit byte-by-byte zeroing loop.

## How to build

```bash
# Build and test kernel (from kernel/ directory)
cd kernel
make clean && make iso
make run-bios-serial

# If you have a CPIO initramfs image already built (repo top-level Makefile can generate one),
# pass it explicitly:
make clean && make iso
make INITRAMFS=../build/initramfs/sysbox.cpio run-bios-serial
```

The Makefile uses monacc (../bin/monacc) for C files and GNU as for assembly files.

## How to run

- Main run: `make run-serial`
- Debug logging (exceptions etc): `make run-bios-serial-log` (writes `build/qemu.log`)

Expected serial output includes:
- `monacc kernel`
- `Entering userland...`
- user message (Phase 2 test)
- `Process exited with code 0`

## Key pitfalls to remember

### monacc-specific issues

- **sizeof(array) bug**: monacc returns element size (8) instead of array size (56 for `uint64_t[7]`). Always compute array sizes manually: `N * sizeof(element)`.
- **No sized register modifiers**: Use separate asm statements for each segment register load instead of combining with `%w0`.
- **lgdt/lidt memory operands**: Build the descriptor table pointer as a byte array and use register-indirect addressing.

### General kernel issues

- BIOS vs UEFI: if SeaBIOS won’t boot the ISO, ensure your host has BIOS GRUB modules installed (Debian/Ubuntu: `grub-pc-bin`).
- Multiboot2 section flags: the Multiboot2 header section must be allocatable (`"a"`) or the ELF LOAD segment may start at `VirtAddr=0`, causing subtle catastrophic crashes.
- Accidental SSE/x87 in early kernel: the compiler may emit `xmm` instructions before you’ve enabled FPU/SSE, leading to #UD and triple faults. Either initialize FPU/SSE early or keep early CFLAGS disabling them.
- Embedded user blobs: ensure `userprog_end` is placed after all bytes (including strings) so the kernel copies code+data.

### Interrupts (current bring-up constraint)

- If interrupts are enabled in ring3 before remapping/masking the legacy PIC (or switching to APIC),
  hardware IRQs can arrive on vectors overlapping CPU exceptions (0x08-0x0f), causing cascaded faults.

## Suggested next steps

- Proper IRQ infrastructure: PIC remap+mask (or APIC) + IRQ handlers, then optionally re-enable ring3 interrupts
- Reduce syscall debug noise (gate or rate-limit syscall logging)
- Phase 6+: fork/wait + scheduler + pipes to support `sh` pipelines
