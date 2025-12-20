.section .text
.code64

.global outb
outb:
    mov %di, %dx
    mov %sil, %al
    outb %al, %dx
    ret

.global inb
inb:
    mov %di, %dx
    inb %dx, %al
    movzbq %al, %rax
    ret

.global outl
outl:
    mov %di, %dx
    mov %esi, %eax
    outl %eax, %dx
    ret

.global lgdt
lgdt:
    lgdt (%rdi)
    ret

.global lidt
lidt:
    lidt (%rdi)
    ret

.global ltr
ltr:
    ltr %di
    ret

.global disable_interrupts
disable_interrupts:
    cli
    ret

.global read_cr2
read_cr2:
    mov %cr2, %rax
    ret

.global halt_forever
halt_forever:
    cli
1:
    hlt
    jmp 1b

/* Enter ring 3 using an iretq frame.
 * Args:
 *   rdi = user RIP
 *   rsi = user RSP
 */
.global enter_user
enter_user:
    cli

    /* Load user data selector into segment regs (mostly ignored in long mode, but keep consistent). */
    mov $0x23, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs

    /* Build iretq frame: SS, RSP, RFLAGS, CS, RIP (so RIP is on top). */
    pushq $0x23
    pushq %rsi
    pushfq
    orq $0x200, (%rsp)   /* IF */
    pushq $0x1b
    pushq %rdi

    iretq

1:
    hlt
    jmp 1b
