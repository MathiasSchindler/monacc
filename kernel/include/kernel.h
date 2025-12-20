#pragma once

#include <stdint.h>
#include <stddef.h>

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
uint64_t read_cr2(void);
__attribute__((noreturn)) void halt_forever(void);

void syscall_init(void);

__attribute__((noreturn)) void enter_user(uint64_t user_rip, uint64_t user_rsp);

__attribute__((noreturn)) void kmain(void);

void serial_putc(char c);
char serial_getc(void);
void serial_write(const char *s);

/* Physical memory manager */
void pmm_init(void);
uint64_t pmm_alloc_page(void);
void pmm_free_page(uint64_t paddr);
uint64_t pmm_alloc_pages(uint32_t n);
void pmm_free_pages(uint64_t paddr, uint32_t n);

/* Reserve an explicit physical range (identity-mapped): returns 0 on success. */
int pmm_reserve_pages(uint64_t paddr, uint32_t n);

/* Minimal ELF loader (ET_EXEC, PT_LOAD). Returns 0 on success. */
int elf_load_exec(const uint8_t *img, uint64_t img_sz, uint64_t *entry_out, uint64_t *brk_init_out);

/* Multiboot2 boot info (set by boot/multiboot2.S). */
extern uint64_t mb2_info_ptr;

int mb2_find_first_module(uint64_t mb2_info_ptr, uint64_t *mod_start_out, uint64_t *mod_end_out);

int cpio_newc_find(const uint8_t *cpio, uint64_t cpio_sz, const char *path,
			  const uint8_t **data_out, uint64_t *size_out);
