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

static inline void outb(uint16_t port, uint8_t val) {
	__asm__ volatile ("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
	uint8_t ret;
	__asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
	return ret;
}

static inline void outl(uint16_t port, uint32_t val) {
	__asm__ volatile ("outl %0, %1" :: "a"(val), "Nd"(port));
}

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
