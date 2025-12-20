/* Multiboot2 + minimal 32->64 transition, then call kmain().
 * Booted by GRUB/Limine as a Multiboot2 kernel.
 */

.set MB2_MAGIC, 0xE85250D6
.set MB2_ARCH,  0

.section .multiboot2,"a"
.align 8
mb2_header:
	.long MB2_MAGIC
	.long MB2_ARCH
	.long mb2_header_end - mb2_header
	.long -(MB2_MAGIC + MB2_ARCH + (mb2_header_end - mb2_header))

	/* end tag */
	.short 0
	.short 0
	.long 8
mb2_header_end:

.section .text
.code32
.global _start
_start:
	cli

	/* Multiboot2: EBX points to the boot info structure. Save it before we clobber regs. */
	movl %ebx, mb2_info_ptr

	/* Temporary 32-bit stack. */
	mov $stack_top, %esp

	/* Build minimal identity-mapped page tables (first 1GiB via 2MiB pages). */
	/* PML4[0] -> PDPT */
	mov $pdpt, %eax
	or  $0x007, %eax
	movl %eax, pml4
	movl $0, pml4+4

	/* PDPT[0] -> PD */
	mov $pd, %eax
	or  $0x007, %eax
	movl %eax, pdpt
	movl $0, pdpt+4

	/* PD[i] -> 2MiB pages identity-mapped */
	xor %ecx, %ecx
.pd_fill_loop:
	mov %ecx, %eax
	shl $21, %eax              /* i * 2MiB */
	or  $0x083, %eax           /* present|write|huge */
	or  $0x004, %eax           /* user */
	movl %eax, pd(,%ecx,8)
	movl $0, pd+4(,%ecx,8)
	inc %ecx
	cmp $512, %ecx
	jne .pd_fill_loop

	/* Load GDT (contains 64-bit code/data segments). */
	lgdt gdt64_ptr

	/* Enable PAE. */
	mov %cr4, %eax
	or  $(1 << 5), %eax
	mov %eax, %cr4

	/* Load CR3 with PML4. */
	mov $pml4, %eax
	mov %eax, %cr3

	/* Enable long mode in EFER. */
	mov $0xC0000080, %ecx
	rdmsr
	or  $(1 << 8), %eax
	wrmsr

	/* Enable paging (CR0.PG). */
	mov %cr0, %eax
	or  $(1 << 31), %eax
	mov %eax, %cr0

	/* Far jump to 64-bit code segment to enter long mode. */
	ljmp $0x08, $long_mode_start

.code64
long_mode_start:
	/* Set data segments. */
	mov $0x10, %ax
	mov %ax, %ds
	mov %ax, %es
	mov %ax, %ss
	mov %ax, %fs
	mov %ax, %gs

	/* 64-bit stack. */
	lea stack_top(%rip), %rsp

	.extern kmain
	call kmain

.hang:
	hlt
	jmp .hang

/* 64-bit GDT */
.align 8
gdt64:
	.quad 0
	/* 0x08: 64-bit code segment */
	.quad 0x00A09A000000FFFF
	/* 0x10: data segment */
	.quad 0x00CF92000000FFFF

gdt64_ptr:
	.word (gdt64_end - gdt64 - 1)
	.quad gdt64

gdt64_end:

.section .bss
/* Multiboot2 info pointer (physical address, identity-mapped). */
.align 8
.global mb2_info_ptr
mb2_info_ptr:
	.quad 0

/* Identity map the first 1GiB using 2MiB pages. */
.align 4096
pml4:
	.skip 4096
.align 4096
pdpt:
	.skip 4096
.align 4096
pd:
	.skip 4096

/* Stack */
.align 16
stack_bottom:
	.skip 16384
stack_top:
