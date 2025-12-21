OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

SECTIONS {
	. = 0x00100000;

	/* Multiboot2 header must be within the first 32KiB of the image. */
	.multiboot2 ALIGN(8) : {
		KEEP(*(.multiboot2))
	}

	/* Xen PVH ELF notes (needed for qemu -kernel direct boot). */
	.note ALIGN(4) : {
		KEEP(*(.note.*))
	}

	.text ALIGN(16) : {
		*(.text .text.*)
	}

	.rodata ALIGN(16) : {
		*(.rodata .rodata.*)
	}

	.data ALIGN(16) : {
		*(.data .data.*)
	}

	.bss ALIGN(16) : {
		*(.bss .bss.*)
		*(COMMON)
	}
}
