.section .rodata
.align 16

/* A real monacc-built ELF executable, embedded as raw bytes.
 * The Makefile assembles this with cwd=kernel/, so paths are relative to kernel/.
 */
.global user_elf_echo_start
.global user_elf_echo_end

user_elf_echo_start:
    .incbin "../bin/echo"
user_elf_echo_end:
