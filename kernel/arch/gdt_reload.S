.section .text
.code64

/* Reload data segments and CS after installing a new GDT.
 * Args:
 *   rdi = code selector (low 16 bits)
 *   rsi = data selector (low 16 bits)
 */
.global gdt_reload
gdt_reload:
    mov %si, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss

    /* Far return to reload CS: push CS, push RIP, lretq */
    movzwq %di, %rax
    pushq %rax
    leaq 1f(%rip), %rax
    pushq %rax
    lretq
1:
    ret
