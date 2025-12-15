# monacc kernel - Implementation Plan

A minimal kernel for Linux x86_64 syscall-compatible userland, designed to run monacc-built tools.

## Goals

1. **Run monacc userland** — Execute the existing 70 tools without modification
2. **Minimal footprint** — Target <100KB kernel binary
3. **Self-hosted** — Eventually compile with monacc itself
4. **QEMU-first** — No real hardware support required
5. **Educational** — Clear, simple code over performance

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

This plan uses **`int 0x80` first** (Phases 1–2), then optionally upgrades to **`SYSCALL/SYSRET`** once processes/scheduling exist.

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
- TSS for kernel stack on ring transitions (used by interrupt gates)
- Syscall dispatch table (stub for now)
- `exit(code)` syscall → print exit code, halt

**Test program** (`test_exit.c`):
```c
void _start(void) {
   // Raw syscall: exit(42)
   // Phase 1 uses int 0x80 for syscalls.
   asm volatile(
      "mov $60, %rax\n"
      "mov $42, %rdi\n"
      "int $0x80\n"
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

## Phase 3: Memory Management

**Goal**: Support `mmap()` for heap allocation.

**New components**:
- Physical page allocator (bitmap or free list)
- Virtual address space per process (page tables)
- `mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)`
- Simple break-style allocator fallback

**Syscalls**: `mmap` (9), `munmap` (11) [optional]

**Test**: Any tool using `monacc_malloc()` (the compiler itself)

**Estimated size**: ~15KB

---

## Phase 4: In-Memory Filesystem (ramfs)

**Goal**: Mount initramfs, support file operations.

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

**New components**:
- ELF64 loader (parse headers, map PT_LOAD segments)
- Process structure (pid, page tables, fd table, cwd)
- `execve()` - replace current process image
- Argument/environment passing (set up user stack)
- `/init` as PID 1

**Syscalls**: `execve` (59)

**Test**: Kernel loads `/init` which does `execve("/bin/sh", ...)`

**Estimated size**: ~35KB

---

## Phase 6: fork() and wait()

**Goal**: Multi-process support.

**New components**:
- Process table (fixed size, e.g., 64 processes)
- `fork()` - clone process (copy page tables, fd table)
- `wait4()` - wait for child termination
- Simple round-robin scheduler
- Timer interrupt for preemption
- `getpid()`, `getppid()` (trivial)

**Syscalls**: `fork` (57), `vfork` (58), `wait4` (61), `getpid` (39), `getppid` (110)

**Test**: Shell can run commands: `sh -c "echo hello"`

**Estimated size**: ~45KB

---

## Phase 7: Pipes

**Goal**: Pipeline support for shell.

**New components**:
- Pipe buffer (circular, ~4KB)
- `pipe2()` - create pipe fds
- `dup2()` - duplicate fd
- Reader/writer blocking

**Syscalls**: `pipe2` (293), `dup2` (33)

**Test**: `echo hello | cat`

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

## Phase 9: Self-Hosting

**Goal**: Compile the kernel with monacc.

**Challenges**:
- Kernel needs inline asm for boot code (monacc doesn't support it)
- Solution: Keep `boot.S` as hand-written assembly, compile C parts with monacc

**Approach**:
1. Write kernel C code compatible with monacc's C subset
2. Use `nasm` or hand-written `.S` for boot stub
3. Link with `ld` (already used by monacc)

---

## Development Environment

### Build

```makefile
# kernel/Makefile
CC = gcc  # Later: ../bin/monacc
AS = as
LD = ld

CFLAGS = -ffreestanding -nostdlib -mno-red-zone -mcmodel=kernel \
         -fno-stack-protector -fno-pic -O2

kernel.elf: boot.o main.o serial.o ...
	$(LD) -T link.ld -o $@ $^
```

Notes:

- Keep early C strictly freestanding (`-ffreestanding`, no libc). Avoid compiler builtins that might pull in runtime.
- Prefer `clang` or `gcc` as host compiler for now; the *kernel C subset* should stay compatible with monacc for the self-hosting milestone.
- If using a bootloader (Option A), the build produces an ISO (or a raw disk image) and QEMU boots that image.

### Test

```bash
# Boot (Multiboot2 via bootloader ISO)
qemu-system-x86_64 -cdrom build/kernel.iso -serial stdio -display none

# Debug with GDB
qemu-system-x86_64 -cdrom build/kernel.iso -serial stdio -display none -s -S &
gdb build/kernel.elf -ex "target remote :1234"
```

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
│   ├── syscall.c        # Syscall dispatch (int 0x80 first; SYSCALL later)
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
| 8 | Full syscalls | ~3500 | All 70 tools |
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
