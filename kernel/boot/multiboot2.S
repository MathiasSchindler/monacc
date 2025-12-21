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

/* Xen PVH direct-boot entry note.
 * QEMU requires this note to load an uncompressed ELF via -kernel.
 * See: https://xenbits.xen.org/docs/unstable/misc/pvh.html
 */
.section .note.Xen,"a"
.align 4
/* ELF note header: namesz, descsz, type */
	.long 4                      /* "Xen\0" */
	.long 4                      /* 32-bit entry address */
	.long 0x12                   /* XEN_ELFNOTE_PHYS32_ENTRY */
	.asciz "Xen"
	.align 4
	.long pvh_start32
	.align 4

.section .text
.code32
.global _start
_start:
	cli

	/* Multiboot2: EBX points to the boot info structure. Save it before we clobber regs. */
	movl %ebx, mb2_info_ptr
	/* Not PVH. */
	movl $0, pvh_start_info_ptr

common_start32:
	/* From here on, boot paths share the same 32->64 transition. */

	/* Temporary 32-bit stack. */
	mov $stack_top, %esp

	/* Build minimal identity-mapped page tables (first 4GiB via 2MiB pages).
	 * GRUB may place Multiboot2 modules (e.g. initramfs) above 1GiB.
	 */
	/* PML4[0] -> PDPT */
	mov $pdpt, %eax
	or  $0x007, %eax
	movl %eax, pml4
	movl $0, pml4+4

	/* PDPT[0..3] -> PD0..PD3 */
	mov $pd0, %eax
	or  $0x007, %eax
	movl %eax, pdpt
	movl $0, pdpt+4

	mov $pd1, %eax
	or  $0x007, %eax
	movl %eax, pdpt+8
	movl $0, pdpt+12

	mov $pd2, %eax
	or  $0x007, %eax
	movl %eax, pdpt+16
	movl $0, pdpt+20

	mov $pd3, %eax
	or  $0x007, %eax
	movl %eax, pdpt+24
	movl $0, pdpt+28

	/* PDx[i] -> 2MiB pages identity-mapped */
	/* 0..1GiB */
	xor %ecx, %ecx
.pd0_fill_loop:
	mov %ecx, %eax
	shl $21, %eax              /* i * 2MiB */
	or  $0x087, %eax           /* present|write|user|huge */
	movl %eax, pd0(,%ecx,8)
	movl $0, pd0+4(,%ecx,8)
	inc %ecx
	cmp $512, %ecx
	jne .pd0_fill_loop

	/* 1..2GiB */
	xor %ecx, %ecx
.pd1_fill_loop:
	mov %ecx, %eax
	shl $21, %eax
	add $0x40000000, %eax
	or  $0x087, %eax
	movl %eax, pd1(,%ecx,8)
	movl $0, pd1+4(,%ecx,8)
	inc %ecx
	cmp $512, %ecx
	jne .pd1_fill_loop

	/* 2..3GiB */
	xor %ecx, %ecx
.pd2_fill_loop:
	mov %ecx, %eax
	shl $21, %eax
	add $0x80000000, %eax
	or  $0x087, %eax
	movl %eax, pd2(,%ecx,8)
	movl $0, pd2+4(,%ecx,8)
	inc %ecx
	cmp $512, %ecx
	jne .pd2_fill_loop

	/* 3..4GiB */
	xor %ecx, %ecx
.pd3_fill_loop:
	mov %ecx, %eax
	shl $21, %eax
	add $0xC0000000, %eax
	or  $0x087, %eax
	movl %eax, pd3(,%ecx,8)
	movl $0, pd3+4(,%ecx,8)
	inc %ecx
	cmp $512, %ecx
	jne .pd3_fill_loop

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

	/* Enable x87/SSE (userland tools like sh may use XMM instructions).
	 * - Clear CR0.EM and CR0.TS; set CR0.MP
	 * - Set CR4.OSFXSR and CR4.OSXMMEXCPT
	 */
	mov %cr0, %rax
	and $0xfffffffffffffff3, %rax /* clear EM(2) and TS(3) */
	or  $0x2, %rax               /* set MP(1) */
	mov %rax, %cr0
	mov %cr4, %rax
	or  $((1<<9) | (1<<10)), %rax
	mov %rax, %cr4
	fninit

	/* 64-bit stack. */
	lea stack_top(%rip), %rsp

	.extern kmain
	call kmain

.hang:
	hlt
	jmp .hang

/* Xen PVH entry point.
 * Machine state is 32-bit protected mode; EBX points to hvm_start_info.
 */
.global pvh_start32
pvh_start32:
	cli
	/* Do not touch mb2_info_ptr; PVH is not Multiboot2. */
	movl %ebx, pvh_start_info_ptr
	jmp common_start32

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

/* PVH start info pointer (physical address, identity-mapped). */
.align 8
.global pvh_start_info_ptr
pvh_start_info_ptr:
	.quad 0

	/* Identity map the first 4GiB using 2MiB pages. */
.align 4096
pml4:
	.skip 4096
.align 4096
pdpt:
	.skip 4096
.align 4096
	/* 4x page directories (each covers 1GiB with 2MiB pages). */
pd0:
	.skip 4096
	.align 4096
pd1:
	.skip 4096
	.align 4096
pd2:
	.skip 4096
	.align 4096
pd3:
	.skip 4096

/* Stack */
.align 16
stack_bottom:
	.skip 16384
stack_top:
