#pragma once

#include <stdint.h>
#include <stddef.h>

// Linux x86_64 ABI constants (subset used by monacc userland).

// openat(2)
#define AT_FDCWD (-100)

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define O_NONBLOCK 00004000
#define O_NOFOLLOW 0400000
#define O_CLOEXEC 02000000
#define O_DIRECTORY 0200000

// socket(2) (Linux values)
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_NONBLOCK 00004000
#define SOCK_CLOEXEC 02000000

// poll(2)
struct mc_pollfd {
	int32_t fd;
	int16_t events;
	int16_t revents;
};

#define POLLIN 0x0001
#define POLLOUT 0x0004
#define POLLERR 0x0008
#define POLLHUP 0x0010

// *at(2)
#define AT_SYMLINK_NOFOLLOW 0x100

// lseek(2)
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

// stat(2) bits
#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFDIR 0040000
#define S_IFLNK 0120000

// Linux x86_64 struct stat (kernel ABI). Matches core/mc_syscall.h.
struct mc_stat {
	uint64_t st_dev;
	uint64_t st_ino;
	uint64_t st_nlink;
	uint32_t st_mode;
	uint32_t st_uid;
	uint32_t st_gid;
	uint32_t __pad0;
	uint64_t st_rdev;
	int64_t st_size;
	int64_t st_blksize;
	int64_t st_blocks;
	uint64_t st_atime;
	uint64_t st_atime_nsec;
	uint64_t st_mtime;
	uint64_t st_mtime_nsec;
	uint64_t st_ctime;
	uint64_t st_ctime_nsec;
	int64_t __unused[3];
};

// uname(2)
struct mc_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

// getdents64(2) entry (Linux kernel ABI)
struct mc_dirent64 {
	uint64_t d_ino;
	int64_t d_off;
	uint16_t d_reclen;
	uint8_t d_type;
	char d_name[];
} __attribute__((packed));

// d_type values (DT_*) used by ls
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10

/* Page size */
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12

/* mmap flags (Linux ABI) */
#define PROT_READ    0x1
#define PROT_WRITE   0x2
#define PROT_EXEC    0x4
#define MAP_PRIVATE  0x02
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED   ((void *)-1)

/* Low-level I/O and descriptor-table helpers are implemented in .S files.
 * This keeps monacc-compiled C free of privileged/rare instructions that the
 * internal assembler may not support yet.
 */
void outb(uint16_t port, uint8_t val);
uint8_t inb(uint16_t port);
void outl(uint16_t port, uint32_t val);

void lgdt(void *gdtr);
void lidt(void *idtr);
void ltr(uint16_t sel);

void disable_interrupts(void);
uint64_t rdmsr(uint32_t msr);
void wrmsr(uint32_t msr, uint64_t val);
uint64_t rdtsc64(void);
uint64_t read_cr2(void);
__attribute__((noreturn)) void halt_forever(void);

void syscall_init(void);

__attribute__((noreturn)) void enter_user(uint64_t user_rip, uint64_t user_rsp);

__attribute__((noreturn)) void kmain(void);

void serial_putc(char c);
char serial_getc(void);
void serial_write(const char *s);

// Optional second UART (COM2) used for host-proxy networking.
void serial2_init(void);
void serial2_putc(char c);
char serial2_getc(void);
int serial2_try_getc(char *out);
void serial2_write(const void *buf, uint64_t n);
void serial2_read(void *buf, uint64_t n);

/* Legacy PIC (8259A) support.
 * For bring-up we remap PIC away from exception vectors and mask all IRQs.
 */
void pic_init(void);
void irq_handler(uint64_t vec);

/* Physical memory manager */
void pmm_init(void);
uint64_t pmm_alloc_page(void);
void pmm_free_page(uint64_t paddr);
uint64_t pmm_alloc_pages(uint32_t n);
uint64_t pmm_alloc_pages_high(uint32_t n);
void pmm_free_pages(uint64_t paddr, uint32_t n);

/* Reserve an explicit physical range (identity-mapped): returns 0 on success. */
int pmm_reserve_pages(uint64_t paddr, uint32_t n);

/* Minimal ELF loader (ET_EXEC, PT_LOAD). Returns 0 on success. */
int elf_load_exec(const uint8_t *img, uint64_t img_sz, uint64_t *entry_out, uint64_t *brk_init_out);

/* Multiboot2 boot info (set by boot/multiboot2.S). */
extern uint64_t mb2_info_ptr;

/* Xen PVH boot start info (set by boot/multiboot2.S when booted via PVH). */
extern uint64_t pvh_start_info_ptr;

int mb2_find_first_module(uint64_t mb2_info_ptr, uint64_t *mod_start_out, uint64_t *mod_end_out);

int pvh_find_first_module(uint64_t pvh_start_info_ptr, uint64_t *mod_start_out, uint64_t *mod_end_out);

int cpio_newc_find(const uint8_t *cpio, uint64_t cpio_sz, const char *path,
			  const uint8_t **data_out, uint64_t *size_out);

int cpio_newc_stat(const uint8_t *cpio, uint64_t cpio_sz, const char *path,
			  uint32_t *mode_out, uint64_t *size_out);

// Returns 1 if any entry exists under dirpath (dirpath + "/" prefix), else 0.
int cpio_newc_has_prefix(const uint8_t *cpio, uint64_t cpio_sz, const char *dirpath);

// Iterate immediate children of dirpath (no leading '/', no trailing '/'; root is "").
// Returns 1 and writes name/type on success, 0 on end, <0 on error.
int cpio_newc_dir_next(const uint8_t *cpio, uint64_t cpio_sz, const char *dirpath,
			       uint64_t *scan_off_inout, char *name_out, uint64_t name_cap,
			       uint8_t *dtype_out);
