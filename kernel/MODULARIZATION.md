# Kernel Backend Modularization

This document describes the modularization of the monacc kernel backend.

## Summary

The kernel backend has been reorganized from a monolithic `main.c` file (2092 lines) into a modular architecture with clear separation of concerns:

- **main.c**: 189 lines (91% reduction) - now only contains kmain() and initialization
- **proc/**: Process management and scheduling (2 modules, ~1.3KB total)
- **sys/**: System call handling and utilities (2 modules, ~9.9KB total)
- **fs/**: File system operations (VFS layer) (1 module, ~5.5KB)

## Module Structure

### Process Management (`proc/`)

#### `proc/process.c`
- Process allocation/deallocation (`kproc_alloc`, `kproc_free`)
- Process image backup management (`kproc_ensure_img_backup`, `kproc_img_save/restore`)
- Stack save/restore operations (`kproc_stack_save/restore`)
- Manages global process table `g_procs[]` and current process `g_cur`

#### `proc/sched.c`
- Round-robin scheduler (`kproc_pick_next`)
- Context switching (`kproc_switch`)
- Process lifecycle management (`kproc_die_if_no_runnable`)

### System Calls (`sys/`)

#### `sys/syscalls.c` (1187 lines)
- Main syscall dispatcher (`syscall_handler`)
- Implements all syscalls:
  - I/O: read, write, close, lseek, ioctl
  - Files: openat, fstat, newfstatat, faccessat, getdents64
  - Process: fork, execve, wait4, exit, getpid, getppid
  - Memory: mmap, munmap
  - Pipes: pipe2, dup2
  - Misc: getcwd, chdir, uname, getuid, getgid, getgroups

#### `sys/utils.c`
- Memory operations: `kmemcpy`, `kmemset`
- String operations: `kstrnlen`, `kcopy_cstr`, `kstrcpy_cap`
- Path resolution: `resolve_path`, `skip_leading_slash`, `is_dot`, `is_dotdot`
- Alignment: `align_up_u64`, `align_down_u64`
- Stat helpers: `kstat_clear`, `kstat_fill`
- User stack operations: `user_stack_push_bytes`, `user_stack_push_u64`
- Debug output: `serial_write_u64_dec`, `serial_write_hex`, `ktrace_sys`
- Hashing: `fnv1a64`

### File System (`fs/`)

#### `fs/vfs.c`
- File descriptor table management (`kfd_*` functions)
- File object management (`kfile_*` functions)
- Pipe management (`kpipe_*` functions)
- Reference counting for files and pipes
- Manages global file table `g_kfiles[]` and pipe table `g_pipes[]`

#### `fs/cpio_newc.c` (existing)
- CPIO newc format parsing for initramfs

### Headers (`include/`)

#### `include/proc.h`
- Process structures and enums
- Process management function declarations
- Process table exports

#### `include/fs.h`
- File and pipe structures
- VFS function declarations
- File/pipe table exports

#### `include/sys.h`
- Syscall handler declaration
- Utility function declarations
- Syscall-related constants

## Benefits

1. **Maintainability**: Each module has a clear, focused responsibility
2. **Readability**: Easier to navigate and understand the codebase
3. **Testability**: Modules can be tested independently
4. **Extensibility**: New features can be added to appropriate modules
5. **Build time**: Incremental compilation of changed modules only

## Alignment with kernel/plan.md

The modularization follows the file structure outlined in `kernel/plan.md`:

```
kernel/
├── proc/
│   ├── process.c        # Process management ✓
│   └── sched.c          # Scheduler ✓
├── sys/
│   ├── syscalls.c       # Syscall dispatcher ✓
│   └── utils.c          # Helper functions ✓
└── fs/
    └── vfs.c            # VFS layer ✓
```

Future work (from plan.md) can add:
- `proc/fork.c` - Extract fork/exec/wait logic
- `sys/sys_io.c` - Extract I/O syscalls
- `sys/sys_proc.c` - Extract process syscalls
- `sys/sys_mem.c` - Extract memory syscalls
- `sys/sys_fs.c` - Extract filesystem syscalls
- `sys/sys_misc.c` - Extract misc syscalls

## Build System

The Makefile has been updated to compile each module separately:
- Added build rules for `$(BUILD)/proc/*.o`
- Added build rules for `$(BUILD)/sys/*.o`
- Added build rules for `$(BUILD)/fs/vfs.o`
- Updated dependencies to include new headers

## Testing

- Kernel builds successfully with monacc
- Final kernel size: 90KB (under 100KB goal)
- All symbols properly linked (no undefined symbols)
- Module interdependencies correctly handled via headers
