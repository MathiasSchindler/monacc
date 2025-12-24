#ifndef SYS_H
#define SYS_H

#include "kernel.h"
#include "proc.h"

#ifndef KDEBUG_SYSCALLS
#define KDEBUG_SYSCALLS 0
#endif

/* Syscall handler entry point */
void syscall_handler(struct regs *r);

/* Helper functions used by syscalls */
void kmemcpy(void *dst, const void *src, size_t n);
void kmemset(void *dst, uint8_t v, uint64_t n);
uint64_t kstrnlen(const char *s, uint64_t maxn);
int kcopy_cstr(char *dst, uint64_t cap, const char *src);
const char *skip_leading_slash(const char *s);
const char *skip_dot_slash2(const char *s);
int is_dot(const char *s);
int is_dotdot(const char *s);
int resolve_path(char *out, uint64_t cap, int dirfd, const char *pathname);
void kstrcpy_cap(char *dst, uint64_t cap, const char *src);
uint64_t align_up_u64(uint64_t v, uint64_t a);
uint64_t align_down_u64(uint64_t v, uint64_t a);
uint64_t fnv1a64(const char *s);
void kstat_clear(struct mc_stat *st);
void kstat_fill(struct mc_stat *st, uint32_t mode, uint64_t size);
uint64_t user_stack_push_bytes(uint64_t sp, const void *data, uint64_t n);
uint64_t user_stack_push_u64(uint64_t sp, uint64_t v);
void serial_write_u64_dec(uint64_t v);
void serial_write_hex(uint64_t v);
void ktrace_sys(const char *name, uint64_t nr);

/* From arch/syscall_entry.S */
extern uint64_t syscall_user_rsp;
extern uint64_t syscall_kstack_top;
extern uint64_t k_current_pid;

#endif
