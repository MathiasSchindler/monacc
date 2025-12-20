# monacc kernel - Implementation Plan

A minimal kernel for Linux x86_64 syscall-compatible userland, designed to run monacc-built tools.

## Goals

1. **Run monacc userland** — Execute the existing tool suite (currently 85 tools) without modification
2. **Minimal footprint** — Target <100KB kernel binary
3. **Self-hosted** — Compile kernel C code with monacc ✓ (achieved as of Phase 2!)
4. **QEMU-first** — No real hardware support required
5. **Educational** — Clear, simple code over performance

## Current Status

### Bring-up snapshot (Dec 2025)

- Initramfs is loaded as a Multiboot2 module (uncompressed CPIO `newc`) and exposed through a minimal read-only file + directory layer.
- The syscall surface is now sufficient to run real tools from initramfs, including recursive directory traversal.
- `ls /`, `ls -l /`, and `ls -R /` have been validated end-to-end.
- User stack size matters: tools like `ls` and `sh` use large on-stack buffers.
- PIC is remapped to 0x20-0x2F and all IRQ lines are masked; IRQ stubs exist to ACK (EOI) safely if needed.
- Ring 3 starts with IF=1 again (safe while IRQs are masked; later work can selectively unmask timer/serial IRQs).

Newly validated (since the original Phase 5 bring-up):

- `fork()`/`wait4()` implemented sufficiently for real shell usage
- `pipe2()`/`dup2()` implemented sufficiently for pipelines
- `/bin/sh -c "cd /bin; /bin/pwd; /bin/echo hello | /bin/cat"` now completes and prints expected output
- Interactive `bin/sh` works as PID 1 (serial prompt + basic line editing)
- `cat hello.txt` works from the initramfs
- `mandelbrot` runs successfully
- Minimal tty detection (`ioctl(TCGETS)`) is implemented so `sh` enables interactive mode

**The kernel now compiles with monacc!** As of Phase 2, all C files are compiled with `../bin/monacc`, with only assembly files (`.S`) using GNU as.

Note: monacc does not currently ship its own `as`/`ld`. The kernel build intentionally uses the host binutils (`as`, `ld`) for `.S` and final link, and keeps monacc-compiled C free of privileged/rare instructions.

### monacc limitations discovered

The following issues were encountered and worked around:

1. **Privileged/rare instructions in inline asm may be rejected**
   - Impact: instructions like `cli`, `hlt`, and `mov %cr2, ...` triggered internal-assembler errors when used from C
   - Workaround: implement low-level helpers in GNU-as `.S` stubs (e.g. `arch/lowlevel.S`) and call them from C

2. **`sizeof(array)` returns pointer size (8) instead of array size**
   - Impact: GDT limit was 7 instead of 55, causing #GP faults
   - Workaround: Hardcode array sizes as `N * element_size`

3. **No `%w` or `%b` operand modifiers in inline asm**
   - Impact: Can't use `movw %w0, %%ds` for sized register operands
   - Workaround: Use separate `__asm__ volatile` statements, push/pop through %r8

4. **Memory operand `"m"` issues with packed structs for `lgdt`/`lidt`**
   - Impact: Unreliable loads of GDTR/IDTR bases when attempted via inline asm memory operands
   - Workaround: use `.S` stubs for `lgdt`/`lidt` so C just passes a pointer

5. **No `__builtin_unreachable()`**
   - Impact: Compiler doesn't know function won't return
   - Workaround: Use a non-returning helper (e.g. `halt_forever()`) implemented in `.S`

6. **`extern` array declarations create local BSS symbols**
   - Impact: `extern unsigned char userprog_start[]` generates local symbol at 0, not external reference
   - Workaround: Declare as function pointer `void userprog_start_func(void)` and cast to uint64_t

7. **`static` local arrays placed on stack, not BSS**
   - Impact: `static uint8_t kstack0[16384]` inside function uses stack space
   - Workaround: Move static arrays to file scope

8. **`sizeof(packed struct)` returns wrong value**
   - Impact: TSS64 should be 104 bytes but monacc returns 112
   - Workaround: Hardcode struct sizes

9. **`__attribute__((packed))` not honored for struct member offsets**
   - Impact: TSS rsp0 placed at offset 8 instead of 4 (natural alignment)
   - Workaround: Use raw byte-level access with explicit offsets

10. **Compound literal struct assignment only copies 8 bytes**
   - Impact: `tss = (struct tss64){0}` only zeros 8 bytes, not full struct
   - Workaround: Use explicit byte-by-byte zeroing loop

## Guiding constraints

- **Minimal host/tool dependencies**: prefer `as`/`ld` + one C compiler.
- **One external boot path (at most)**: use a bootloader only if it materially simplifies early bring-up.
- **Linux-like syscall ABI for userland**: the goal is to run monacc-built ELF binaries without patching them.

## Non-Goals

- Real hardware support (no ACPI, USB, PCI enumeration)
- Networking
- SMP (single CPU only)
- Swap, demand paging, CoW
- POSIX signals beyond SIGPIPE ignore
- Users/permissions (everything runs as "root")

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│  Userland (ring 3)                                  │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                   │
│  │ sh  │ │ cat │ │ ls  │ │ ... │  (monacc tools)   │
│  └──┬──┘ └──┬──┘ └──┬──┘ └──┬──┘                   │
│     │       │       │       │                       │
│     └───────┴───────┴───────┘                       │
│                  │ syscall                          │
├──────────────────┼──────────────────────────────────┤
│  Kernel (ring 0) │                                  │
│                  ▼                                  │
│  ┌────────────────────────────────────────────┐    │
│  │           Syscall Dispatch Table           │    │
│  └────────────────────────────────────────────┘    │
│         │              │              │            │
│    ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐       │
│    │ Process │   │ Filesystem│  │  Memory │       │
│    │  (fork, │   │  (ramfs)  │  │  (mmap) │       │
│    │  exec)  │   │           │  │         │       │
│    └─────────┘   └───────────┘  └─────────┘       │
│                                                    │
│  ┌─────────────────────────────────────────────┐  │
│  │  Hardware Abstraction (serial, timer, MMU)  │  │
│  └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Critical design choices (to avoid rework)

### 1) How the kernel is booted (choose one and stick to it)

There are two common approaches in QEMU; they are *not interchangeable*:

- **A. Multiboot2 via a bootloader (recommended for simplicity)**
   - Bootloader loads an ELF kernel and can also pass an initramfs as a “module”.
   - Typical bootloaders: **GRUB** or **Limine**.
   - QEMU runs an ISO image; you do **not** use `qemu -kernel` for Multiboot2.

- **B. Linux boot protocol (`bzImage`) via QEMU `-kernel`**
   - QEMU’s `-kernel/-initrd/-append` path expects a Linux-style kernel image.
   - This requires implementing the Linux boot protocol (or producing a `bzImage`).
   - Great long-term for “Linux-compatible” boot, but more work up front.

This plan assumes **Option A (Multiboot2 + bootloader)** for Phases 0–5. If we later decide to switch to Option B, it should be treated as a separate milestone.

### 2) Syscall entry mechanism (important x86_64 detail)

On x86_64:

- **`int 0x80` / interrupt gate**: CPU can switch stacks using the TSS (simple, good early).
- **`SYSCALL/SYSRET`**: faster, but **does not automatically switch stacks via the TSS**.
   - You must arrange a safe kernel stack yourself (commonly `swapgs` + per-thread stack pointer in GS).

This kernel now uses **`SYSCALL/SYSRET`** for userland (to match monacc-built binaries) and switches to a dedicated kernel syscall stack in the entry stub. A future scheduler can replace this with a per-thread stack.

---

## Bring-up gotchas (lessons learned)

These are easy-to-hit pitfalls that cause “no output”, reboots, or triple faults.

### Boot + image layout

- **BIOS vs UEFI GRUB tooling**: if your ISO only has UEFI boot and you run QEMU/SeaBIOS, it won’t boot. Install BIOS GRUB modules (e.g. Debian/Ubuntu: `grub-pc-bin`) so `grub-mkrescue` emits a BIOS El Torito image too.
- **Serial-only GRUB**: when running QEMU with `-display none`, make sure `grub.cfg` uses `insmod serial`, `insmod terminal_serial`, and `terminal_output serial` early. Otherwise GRUB may try graphics and complain about video modes.
- **Multiboot2 header must be allocatable**: keep the Multiboot2 header in an allocated section (e.g. `.section .multiboot2,"a"`). If it is non-alloc, it won’t land in the LOAD segment and your ELF PHDR `VirtAddr` can end up as 0 even if the section header says 1MiB — leading to wrong pointers (IDT/GDT/etc) and immediate faults.

### Early CPU/ABI hazards

- **Compiler may emit SSE/x87 even in freestanding code**: on some toolchains/flags, GCC can generate `xmm` instructions (e.g. for struct copies). If CR0/CR4 aren’t configured for FPU/SSE yet, you’ll fault in ring 0 and likely triple-fault without exception handlers. Either (a) fully initialize FPU/SSE early, or (b) compile the early kernel with SSE/MMX/x87 disabled.
- **Syscall register save layout must match**: the C `struct regs` must exactly match the push/pop order in the syscall ISR stub, or syscall args/return values will be mis-decoded.

### Embedded user test programs

- If you embed a user program blob in a section and copy it into user memory, ensure the copied range includes **both code and data** (e.g. string literals). Put the `userprog_end` label after all embedded bytes.

### Debugging workflow

- Prefer deterministic exits: use `isa-debug-exit` (`-device isa-debug-exit,iobase=0xf4,iosize=0x04`) so `exit()` can terminate QEMU without manual interrupts.
- When diagnosing faults, run with `-no-reboot` and QEMU exception logging (`-d int,cpu_reset -D build/qemu.log`) so you don’t lose the last exception context.

### IRQ/interrupt bring-up note

- Enabling interrupts in ring3 before remapping/masking the legacy PIC (or switching to APIC) can deliver IRQs on vectors overlapping CPU exceptions (0x08-0x0f).
   Ensure PIC is remapped to 0x20+ and either mask all IRQs or install handlers before running ring3 with IF=1.

## Phase 0: Bare Metal Hello World

**Goal**: Boot into long mode, print to serial console, halt.

**Deliverables**:
- Multiboot2 header (booted via GRUB/Limine)
- 32-bit bootstrap: set up GDT, enable paging, jump to 64-bit
- 64-bit kernel entry: print "monacc kernel" to COM1
- Kernel halts cleanly

**Syscalls**: None (no userland yet)

**Test**:
```bash
qemu-system-x86_64 -cdrom build/kernel.iso -serial stdio -display none
# Expected: "monacc kernel" on terminal
```

**Files**:
```
kernel/
├── Makefile
├── link.ld         # Linker script
├── boot/
│   └── multiboot2.S  # Multiboot2 header + 32→64 bit transition
└── arch/
   └── serial.c      # COM1 output + early printk
```

**Estimated size**: ~2KB

---

## Phase 1: Syscall Entry + exit()

**Goal**: Enter ring 3, execute minimal userland, return via `exit()` syscall.

**New components**:
- GDT with user segments (ring 3 code/data)
- IDT with syscall handler (**interrupt 0x80** initially)
- IDT with exception handlers (for early fault debugging)
- TSS for kernel stack on ring transitions (used by interrupt gates)
- Syscall dispatch table (stub for now)
- `exit(code)` syscall → print exit code, halt

**Test program** (`test_exit.c`):
```c
void _start(void) {
   // Raw syscall: exit(42)
   asm volatile(
      "mov $60, %rax\n"
      "mov $42, %rdi\n"
   "syscall\n"
      ::: "rax", "rdi");
}
```

**Syscalls**: `exit` (60)

**Test**:
```bash
qemu-system-x86_64 -cdrom build/kernel.iso -serial stdio -display none
# Expected: "Process exited with code 42"
```

**Estimated size**: ~5KB

---

## Phase 2: Serial Console I/O

**Goal**: `write()` to stdout, `read()` from stdin (serial port).

**New components**:
- File descriptor table (hardcoded: 0=stdin, 1=stdout, 2=stderr → serial)
- `write(fd, buf, count)` → serial output
- `read(fd, buf, count)` → serial input (blocking)
- Serial RX can be polled initially; IRQ-driven RX can wait until the IDT/timer work is in place.

**Test program**: Use existing `bin/echo` or minimal test:
```c
int main() {
    char *msg = "Hello from userland!\n";
    // write(1, msg, 21)
    return 0;
}
```

**Syscalls**: `read` (0), `write` (1), `exit` (60)

**Test**: Run compiled echo, see output on serial

**Estimated size**: ~8KB

---

## Phase 3: Memory Management ✓ COMPLETE

**Goal**: Support `mmap()` for heap allocation.

**Status**: COMPLETE!

**Implemented components**:
- Physical page allocator (bitmap-based PMM in `mm/pmm.c`)
  - Manages memory from 4MB to 128MB (31744 pages)
  - Functions: `pmm_init()`, `pmm_alloc_page()`, `pmm_free_page()`, `pmm_alloc_pages()`, `pmm_free_pages()`
- `mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)` - allocates physical pages
- `munmap(addr, len)` - frees pages back to PMM

**Note**: Currently using identity mapping (no virtual memory/page tables yet). Physical pages are returned directly. Full page table support will come in Phase 4.

**Additional monacc workarounds discovered during this phase**:
- `extern` array declarations create local BSS symbols instead of external references
- `static` local arrays placed on stack instead of BSS
- `sizeof(packed struct)` returns incorrect value
- `__attribute__((packed))` not honored for struct member offsets
- Compound literal struct assignment only copies 8 bytes

**Syscalls**: `mmap` (9), `munmap` (11)

**Test**: User program allocates page via mmap, prints success, unmaps, exits

**Files added**:
- `mm/pmm.c` - Physical memory manager
- `user/test_mmap.S` - Test program

**Estimated size**: ~15KB

---

## Phase 4: In-Memory Filesystem (ramfs)

**Goal**: Mount initramfs, support file operations.

**Status**: Implemented as an initramfs-backed read-only filesystem.

Notes:

- The initramfs is a Multiboot2 module containing a CPIO `newc` archive.
- Directories are synthesized from CPIO path prefixes and iterated via `getdents64` (Linux `dirent64`).

**New components**:
- Parse CPIO newc format (same as Linux initramfs)
- In-memory directory tree (inode-like structures)
- File descriptor table (per-process)
- Path resolution with `.` and `..`

**Syscalls**:
- `openat` (257) - open files
- `close` (3) - close fd
- `read` (0) - read from file fd
- `write` (1) - write to fd (stdout for now)
- `lseek` (8) - seek in file
- `fstat` (5) / `newfstatat` (262) - stat files
- `getdents64` (217) - list directory

**Test**: `cat /init`, `ls /bin`

**Estimated size**: ~25KB

---

## Phase 5: Process Execution

**Goal**: Load and execute ELF binaries.

**Status**: Implemented; can exec tools from initramfs (e.g. `kinit` -> `execve("/bin/ls", ["ls","-R","/"], env)`).

**New components**:
- ELF64 loader (parse headers, map PT_LOAD segments)
- Process structure (pid, page tables, fd table, cwd)
- `execve()` - replace current process image
- Argument/environment passing (set up user stack)
- `/init` as PID 1

**Bring-up shortcut (current implementation)**:
- Embed a real monacc-built tool (e.g. `bin/echo`) as a blob via `.incbin`
- Load as **ET_EXEC** at its linked `p_vaddr` (typically `0x400000`) using identity mapping
- Reserve those pages in the PMM so `mmap()` doesn’t hand them out
- Build a minimal initial stack with `argc/argv` and enter ring3 at `e_entry`

Bring-up note:

- Allocate a sufficiently large user stack for real tools (some tools use large on-stack buffers).

**Syscalls**: `execve` (59)

**Test**: Kernel loads `/init` which does `execve("/bin/sh", ...)`

**Estimated size**: ~35KB

Bring-up note (important for Phase 6/7 correctness under identity mapping):

- The kernel currently uses a **single identity-mapped address space**.
- To run multiple processes without per-process page tables, it snapshots/restores:
   - the fixed user image range `[img_base, img_end)` per process
   - the fixed user stack range per process
- The active user stack virtual range is **fixed** (shared VA for all processes);
   each process has a stack backup buffer that is copied in/out by the scheduler.

---

## Phase 6: fork() and wait()

**Goal**: Multi-process support.

**Status**: Implemented (cooperative scheduling; syscall-boundary switching).

**New components**:
- Process table (fixed size)
- `fork()` - clone process state via snapshot/restore (no per-process page tables yet)
- `wait4()` - waits on zombie children
- Simple round-robin scheduler (switches at syscall boundaries)
- PID tracking in exception output

**Syscalls**: `fork` (57), `vfork` (58), `wait4` (61), `getpid` (39), `getppid` (110)

**Test**: Shell can fork/exec children: `sh -c "/bin/pwd"`

**Estimated size**: ~45KB

---

## Phase 7: Pipes

**Goal**: Pipeline support for shell.

**Status**: Implemented enough for `sh` pipelines.

**New components**:
- Pipe buffer
- `pipe2()` - create pipe fds
- `dup2()` - duplicate fd
- Basic reader/writer blocking semantics

**Syscalls**: `pipe2` (293), `dup2` (33)

**Test**: `sh -c "/bin/echo hello | /bin/cat"`

**Estimated size**: ~50KB

---

## Phase 8: Remaining Syscalls

**Goal**: Full tool compatibility.

Implement remaining syscalls as needed:

| Syscall | Used by | Complexity |
|---------|---------|------------|
| `getcwd` | sh, many | Easy (per-process cwd string) |
| `chdir` | sh, cd | Easy |
| `mkdirat` | mkdir | Easy (ramfs modification) |
| `unlinkat` | rm | Easy |
| `renameat` | mv | Medium |
| `linkat`, `symlinkat` | ln | Medium |
| `readlinkat` | readlink | Easy |
| `fchmodat`, `fchownat` | chmod, chown | Store in inode (no enforcement) |
| `faccessat` | test, sh | Check inode exists |
| `getuid`, `getgid`, `getgroups` | id | Return 0 (root) |
| `clock_gettime` | date, time | Read QEMU RTC or PIT counter |
| `nanosleep` | sleep | Busy-wait or timer-based |
| `uname` | uname | Return static strings |
| `kill` | kill | Send signal to process |
| `rt_sigaction` | sh | Just track SIGPIPE ignore |
| `utimensat` | touch | Update inode times |
| `ftruncate` | - | Ramfs truncation |
| `mount` | init | No-op or devfs |
| `statfs` | df | Return static values |
| `sched_getaffinity` | nproc | Return 1 CPU |

**Estimated size**: ~70KB

---

## Phase 9: Self-Hosting ✓ ACHIEVED

**Goal**: Compile the kernel with monacc.

**Status**: COMPLETE as of Phase 2!

All kernel C files now compile with monacc. The approach used:
1. Keep `.S` files (boot/multiboot2.S, arch/isr.S) assembled with GNU as
2. All `.c` files compiled with `../bin/monacc`
3. Link with GNU ld

**Workarounds required** (see "monacc limitations discovered" at top):
- Hardcode array sizes instead of using `sizeof(array)`
- Use separate asm statements for segment register loads
- Build GDTR/IDTR as byte arrays with register-indirect addressing
- Replace `__builtin_unreachable()` with halt loops

---

## Development Environment

### Build

```makefile
# kernel/Makefile
CC = ../bin/monacc  # Now using monacc!
AS = as
LD = ld

CFLAGS = -c -I include  # monacc flags

kernel.elf: boot.o main.o serial.o ...
	$(LD) -T link.ld -o $@ $^
```

Notes:

- All C files are compiled with monacc; only `.S` files use GNU as.
- monacc doesn't need most GCC flags (`-ffreestanding`, `-fno-pic`, etc.) as it's inherently freestanding.
- Watch out for monacc limitations documented in "monacc limitations discovered" section above.

### Test

```bash
# Preferred (from repo root):
make -C kernel run-bios-serial

# Or, from kernel/ directly:
cd kernel
make run-bios-serial

# Boot (Multiboot2 via bootloader ISO)
qemu-system-x86_64 -cdrom build/kernel.iso -serial stdio -display none

# Debug with GDB
qemu-system-x86_64 -cdrom build/kernel.iso -serial stdio -display none -s -S &
gdb build/kernel.elf -ex "target remote :1234"
```

Note: the ISO produced by `grub-mkrescue` embeds GRUB modules and BIOS+UEFI boot images, so it will be much larger than just `kernel.elf` + the initramfs.

Initramfs default: if `release/monacc-dev-initramfs.cpio` exists, `kernel/Makefile` will include it in the ISO by default as a Multiboot2 module.

### Debug Output

Serial port (COM1, 0x3F8) for all debug/printf output. Tools already write to fd 1/2.

---

## File Structure

```
kernel/
├── plan.md              # This file
├── Makefile
├── link.ld              # Linker script
│
├── boot/
│   ├── multiboot2.S     # Multiboot2 header + 32-bit entry
│   └── boot64.S         # 64-bit bootstrap (optional split)
│
├── arch/
│   ├── idt.c            # IDT, interrupt handlers
│   ├── syscall.c        # Syscall init (MSRs) + dispatch (SYSCALL/SYSRET)
│   ├── paging.c         # Page table management
│   └── serial.c         # COM1 driver
│
├── mm/
│   ├── pmm.c            # Physical memory manager
│   ├── vmm.c            # Virtual memory, mmap
│   └── heap.c           # Kernel heap (optional)
│
├── fs/
│   ├── ramfs.c          # In-memory filesystem
│   ├── cpio.c           # CPIO parser
│   └── vfs.c            # VFS layer (minimal)
│
├── proc/
│   ├── process.c        # Process management
│   ├── elf.c            # ELF loader
│   ├── sched.c          # Scheduler
│   └── fork.c           # fork/exec/wait
│
├── sys/
│   ├── sys_io.c         # read/write/open/close
│   ├── sys_proc.c       # fork/exec/exit/wait
│   ├── sys_mem.c        # mmap
│   ├── sys_fs.c         # mkdir/unlink/stat/...
│   └── sys_misc.c       # uname/clock_gettime/...
│
└── include/
    ├── kernel.h         # Core types, panic, printk
    ├── proc.h           # Process structures
    ├── fs.h             # VFS/ramfs structures
    └── mm.h             # Memory management
```

---

## Milestones & Estimates

| Phase | Milestone | LoC Est. | Can Run |
|-------|-----------|----------|---------|
| 0 | Hello serial | ~200 | Nothing (halts) |
| 1 | exit() works | ~400 | Trivial exit-only programs |
| 2 | read/write | ~600 | `echo`, `yes`, `true`, `false` |
| 3 | mmap | ~900 | Programs needing malloc |
| 4 | ramfs | ~1500 | `cat`, `head`, `tail`, `wc` |
| 5 | execve | ~2000 | `init` → `sh` transition |
| 6 | fork/wait | ~2500 | `sh` running commands |
| 7 | pipes | ~2800 | Pipelines work |
| 8 | Full syscalls | ~3500 | All tools (currently 85) |
| 9 | Self-host | - | Compile kernel with monacc |

---

## Open Questions

1. **Timer source**: Use PIT (simple) or APIC (modern but complex)?
   - Recommendation: PIT for simplicity, ~1ms resolution is fine

2. **Memory layout**: Where to put kernel, user space, page tables?
   - Kernel at 0xFFFFFFFF80000000 (higher half)
   - User at 0x400000 (standard Linux)

3. **Initramfs loading**: QEMU `-initrd` places it in memory. Where?
   - With Multiboot2 + bootloader: initramfs is passed as a Multiboot “module”; the boot info provides its address/size.
   - With Linux boot protocol (if we ever switch): initramfs comes from `-initrd` and must be located via the Linux boot params.

4. **Writable ramfs?**: Should writes persist in-memory?
   - Yes, for `/tmp` and shell functionality

5. **Signal support**: Full signals or just SIGPIPE/SIGCHLD?
   - Minimal: SIGPIPE (ignore), SIGCHLD (for wait)

---

## Resources

- [OSDev Wiki](https://wiki.osdev.org/) - x86_64 specifics
- [Multiboot2 Specification](https://www.gnu.org/software/grub/manual/multiboot2/)
- [Linux syscall table](https://filippo.io/linux-syscall-table/)
- [Intel SDM Vol 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) - Paging, interrupts
- [Write Your Own 64-bit OS](http://os.phil-opp.com/) - Rust, but good x86_64 reference

---

## First Steps

1. Decide boot path: **Multiboot2+bootloader (recommended)** vs Linux boot protocol
2. Create `kernel/boot/multiboot2.S` with minimal header + entry
3. Create `kernel/link.ld` and a tiny `kmain()` that prints to COM1
4. Add `kernel/Makefile` targets to build `build/kernel.elf` and `build/kernel.iso`
5. Test with QEMU using `-cdrom build/kernel.iso`

Ready to start Phase 0?

Appendix: notable debugging lesson (Dec 2025)

- Symptom: `/bin/sh` would start, then fault in a forked child inside redirection parsing (`movzbl (%rax),%eax`) with garbage `RAX`.
- Root cause: under identity mapping, an earlier fork implementation cloned the user stack into a different physical/virtual address, but user pointers into the stack remained the original addresses.
- Fix: keep a **fixed virtual stack region** for all processes and snapshot/restore its contents per process on switch/fork/exec.
