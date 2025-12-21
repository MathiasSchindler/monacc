# Eliminating External Boot Dependencies

Date: 2025-12-21

This document describes an incremental plan to eliminate GRUB and other external tools from the kernel boot path, enabling a fully self-contained bootable image for QEMU.

## Current State

The kernel currently requires these external tools for booting:

| Tool | Purpose | Self-contained? |
|------|---------|-----------------|
| `grub-mkrescue` | Creates bootable ISO with GRUB embedded | ❌ External |
| `as` (GNU) | Assembles `.S` files | ❌ External |
| `ld` (GNU) | Links kernel ELF | ❌ External |
| `cpio` | Creates initramfs archive | ❌ External (optional) |

## Goal

Boot the monacc kernel under QEMU with **zero external boot toolchain dependencies** beyond what's already in-tree.

Target state:
- `bin/monacc` compiles all kernel code
- `bin/mkimage` (new tool) creates a bootable image
- `qemu-system-x86_64 -kernel build/kernel.elf ...` boots directly

## Why Not Just Use GRUB?

1. **Project principle**: "Self-contained ecosystem: prefer solutions that reduce external toolchain assumptions" (spec.md §3)
2. **Size**: GRUB ISOs are 5-10MB; the kernel+initramfs is ~500KB
3. **Simplicity**: Direct boot removes an entire layer of complexity
4. **Reproducibility**: Fewer external tools = more predictable builds

---

## Available Boot Paths in QEMU

QEMU x86_64 supports several direct boot mechanisms:

| Method | Header Required | Initramfs | Complexity |
|--------|-----------------|-----------|------------|
| Linux boot protocol (bzImage) | Linux setup header | `-initrd` | Medium |
| PVH (Xen-style) | ELF Note | `-initrd` | Low |
| Multiboot2 (current) | Multiboot2 header | Module | Already done |

**Recommendation: PVH boot**

PVH (Para-Virtualized Hardware) is the simplest path because:
- QEMU 4.0+ supports booting a raw ELF with a PVH ELF Note
- No compression, no setup header, no bootloader
- Already starts in 32-bit protected mode (similar to Multiboot2)
- Initramfs passed via `-initrd`, address provided in start_info struct

---

## Implementation Plan

### Phase 1: Add PVH Boot Support (Keep Multiboot2)

**Goal**: Dual-boot support — both GRUB/Multiboot2 and direct QEMU PVH work.

**Changes**:

1. Add PVH ELF Note to `kernel/boot/multiboot2.S`:
   ```asm
   .section .note.PVH, "a", @note
   .align 4
   .long 4                    /* namesz: "Xen\0" */
   .long 4                    /* descsz: 4-byte entry point */
   .long 0x12                 /* type: XEN_ELFNOTE_PHYS32_ENTRY */
   .asciz "Xen"
   .align 4
   .long _pvh_start           /* 32-bit physical entry point */
   ```

2. Add PVH entry stub in `kernel/boot/pvh.S`:
   ```asm
   .code32
   .global _pvh_start
   _pvh_start:
       /* ESI points to hvm_start_info struct */
       movl %esi, pvh_start_info
       /* Jump to shared 32->64 transition code */
       jmp _start32_common
   ```

3. Refactor `multiboot2.S` to share the 32->64 transition:
   - Extract common code into `_start32_common`
   - Both Multiboot2 and PVH entries converge there

4. Parse `hvm_start_info` for initramfs location (similar to Multiboot2 modules)

**Test**:
```bash
# Multiboot2 (existing, should still work)
make -C kernel run-bios-serial

# PVH direct boot (new)
qemu-system-x86_64 -kernel kernel/build/kernel.elf \
    -initrd release/monacc-dev-initramfs.cpio \
    -serial stdio -display none -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

**Deliverables**:
- `kernel/boot/pvh.S` — PVH entry point
- Modified `kernel/boot/multiboot2.S` — shared 32->64 code
- Modified `kernel/boot/mb2.c` — parse both Multiboot2 and PVH start_info
- New Makefile target: `make run-pvh`

**External tools still needed**: `as`, `ld`

---

### Phase 2: Extend monacc Internal Assembler

**Goal**: Assemble kernel `.S` files with monacc's internal assembler.

**Current limitation**: monacc's internal assembler is intentionally small and rejects privileged/rare instructions (`cli`, `hlt`, `lgdt`, `mov %cr*`, etc.).

**Changes**:

1. Add kernel-mode instruction support to `compiler/monacc_elfobj.c`:
   - `cli`, `sti`, `hlt`
   - `lgdt`, `lidt`, `ltr`
   - `mov` to/from control registers (`%cr0`, `%cr2`, `%cr3`, `%cr4`)
   - `mov` to/from MSRs via `rdmsr`/`wrmsr`
   - `invlpg`
   - `iretq`, `sysretq`

2. Add `.code32` / `.code64` mode switching (kernel boots in 32-bit mode)

3. Add section flags parsing (`.section .name, "flags", @type`)

**Scope control**: Only add instructions actually used in `kernel/boot/*.S` and `kernel/arch/*.S`. Do not aim for full x86 coverage.

**Test**:
```bash
# Build kernel with monacc-only assembly
make -C kernel AS=../bin/monacc
```

**Deliverables**:
- Extended `compiler/monacc_elfobj.c` with privileged instructions
- Kernel `.S` files assemble with `monacc -c`

**External tools still needed**: `ld`

---

### Phase 3: Use monacc Internal Linker for Kernel

**Goal**: Link the kernel ELF with monacc's internal linker.

**Current limitation**: The internal linker (`--link-internal`) is designed for userland ELFs. Kernel linking has additional requirements:
- Custom linker script (`link.ld`)
- Specific section placement (`.multiboot2` must be early)
- Entry point specification

**Changes**:

1. Extend `compiler/monacc_link.c` to support:
   - Basic linker script parsing (or hardcoded kernel layout)
   - `-T link.ld` flag
   - Section ordering control

2. Alternative (simpler): Create a dedicated kernel linker in `tools/klink.c`:
   - Reads multiple `.o` files
   - Applies hardcoded kernel memory layout
   - Outputs a single ELF
   - Much simpler than full linker script support

**Recommendation**: Start with `tools/klink.c` (dedicated kernel linker) rather than extending the compiler's general-purpose linker.

**Test**:
```bash
make -C kernel LD=../bin/klink
```

**Deliverables**:
- `tools/klink.c` — minimal kernel linker
- Kernel links with `bin/klink`

**External tools still needed**: None for kernel build!

---

### Phase 4: Self-Contained Initramfs Tool

**Goal**: Create initramfs without external `cpio`.

**Changes**:

1. Add `tools/mkcpio.c`:
   - Reads a list of files/directories
   - Outputs CPIO newc format
   - Supports stdin input for file list (like `find | mkcpio`)

**Implementation** (simple):
```c
// CPIO newc header: 6-byte magic + fixed-width hex fields
// For each file: header + filename + padding + data + padding
```

**Test**:
```bash
./bin/mkcpio -o initramfs.cpio bin/init bin/sh bin/cat ...
# or
find bin -type f | ./bin/mkcpio -o initramfs.cpio -
```

**Deliverables**:
- `tools/mkcpio.c` — CPIO newc archive creator

---

### Phase 5: Optional ISO Creation

**Goal**: Create bootable ISO without `grub-mkrescue` (for real hardware or VMs that require ISO).

**This phase is optional** — if QEMU `-kernel` is sufficient, skip this.

**Changes**:

1. Add `tools/mkiso.c`:
   - Creates minimal El Torito bootable ISO 9660 image
   - Embeds a tiny boot sector that loads kernel.elf
   - No GRUB, no complex boot menu

2. Implement minimal boot sector in `kernel/boot/bootsect.S`:
   - 512-byte MBR
   - Loads kernel from ISO
   - Jumps to kernel entry

**Complexity warning**: This is significant work. El Torito + ISO 9660 is non-trivial. Consider whether it's worth the effort vs. just using QEMU `-kernel`.

**Alternative**: Accept external ISO tools for the rare case of needing an ISO.

---

## Milestone Summary

| Phase | Description | External Tools Removed | Effort |
|-------|-------------|------------------------|--------|
| 1 | PVH boot support | `grub-mkrescue` | Low |
| 2 | Kernel asm with monacc | `as` | Medium |
| 3 | Kernel link with monacc | `ld` | Medium |
| 4 | In-tree CPIO tool | `cpio` | Low |
| 5 | In-tree ISO tool | (none remaining) | High (optional) |

After Phase 4, the kernel build is fully self-contained for QEMU direct boot.

---

## Updated Makefile Targets

After implementation:

```makefile
# Default: PVH direct boot (no GRUB, no ISO)
run: $(KERNEL_ELF) $(INITRAMFS)
    qemu-system-x86_64 -kernel $(KERNEL_ELF) \
        -initrd $(INITRAMFS) \
        -serial stdio -display none -no-reboot \
        -device isa-debug-exit,iobase=0xf4,iosize=0x04

# Legacy: Multiboot2 via GRUB ISO (requires grub-mkrescue)
run-grub: iso
    qemu-system-x86_64 -cdrom $(BUILD)/kernel.iso ...
```

---

## PVH Start Info Structure

For Phase 1, the kernel needs to parse the PVH `hvm_start_info` struct:

```c
struct hvm_start_info {
    uint32_t magic;          /* 0x336ec578 */
    uint32_t version;        /* 1 */
    uint32_t flags;
    uint32_t nr_modules;
    uint64_t modlist_paddr;  /* array of hvm_modlist_entry */
    uint64_t cmdline_paddr;
    uint64_t rsdp_paddr;
    uint64_t memmap_paddr;
    uint32_t memmap_entries;
    uint32_t reserved;
};

struct hvm_modlist_entry {
    uint64_t paddr;
    uint64_t size;
    uint64_t cmdline_paddr;
    uint64_t reserved;
};
```

The initramfs (from `-initrd`) appears as module 0.

---

## References

- [QEMU Direct Linux Boot](https://www.qemu.org/docs/master/system/linuxboot.html)
- [PVH Boot in QEMU 4.0](https://stefano-garzarella.github.io/posts/2019-08-23-qemu-linux-kernel-pvh/)
- [Xen HVM Start Info](https://xenbits.xen.org/docs/unstable/hypercall/x86_64/include,public,arch-x86,hvm,start_info.h.html)
- [CPIO newc format](https://man.freebsd.org/cgi/man.cgi?query=cpio&sektion=5)

---

## Open Questions

1. **32-bit bootstrap**: PVH starts in 32-bit protected mode. Our existing Multiboot2 32->64 transition code can be reused. Should we unify into a single `boot32.S`?

2. **Memory map**: PVH provides a memory map. Should we use it instead of the hardcoded 4MB-128MB range in the PMM?

3. **Command line**: PVH passes a command line. Should we parse it for debug flags?

4. **Fallback**: Should we keep Multiboot2 support indefinitely for users who need GRUB, or deprecate it once PVH works?

---

## First Steps

1. Create `kernel/boot/pvh.S` with PVH entry point
2. Add PVH ELF Note to existing boot assembly
3. Test with `qemu-system-x86_64 -kernel kernel/build/kernel.elf`
4. If it works, add `make run-pvh` target
5. Document in `kernel/status.md`

Ready to start Phase 1?
