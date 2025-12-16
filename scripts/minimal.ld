/* Minimal linker script for sysbox static ELF binaries.
 * Targets Linux x86_64; produces non-PIE ET_EXEC.
 *
 * Notes:
 * - We intentionally keep a single PT_LOAD segment (RWX) to minimize ELF overhead.
 * - For a size-focused, single-user environment this is acceptable; if you want W^X,
 *   split into separate RX/RW PT_LOADs (adds program-header overhead).
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
	all PT_LOAD FLAGS(7);      /* PF_R | PF_W | PF_X */
}

SECTIONS
{
	/* Place at the usual x86_64 ET_EXEC base; include ELF+PHDR in the first segment. */
	. = 0x400000 + SIZEOF_HEADERS;

	/* Code + read-only data. */
	.text : {
		*(.text .text.*)
		*(.rodata .rodata.*)
	} :all

	/* Initialized data (rare in this codebase, but keep it correct). */
	.data : {
		*(.data .data.*)
		*(.sdata .sdata.*)
	} :all

	/* Uninitialized data (doesn't take file space). */
	.bss (NOLOAD) : ALIGN(8) {
		*(.bss .bss.*)
		*(COMMON)
	} :all

	/* Discard everything we don't need at runtime. */
	/DISCARD/ : {
		*(.note*)
		*(.comment)
		*(.eh_frame*)
		*(.gcc_except_table*)
		*(.gnu*)
	}
}
