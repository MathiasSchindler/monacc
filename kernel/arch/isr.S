.section .text
.code64

.macro PUSH_GPRS
    pushq %rax
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
.endm

.macro POP_GPRS
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
.endm

.macro EXC_NOERR vec
    .global isr\vec
isr\vec:
    /* Normalize to: [gprs...][vector][err][cpu frame...] */
    pushq $0
    pushq $\vec
    PUSH_GPRS
    movq %rsp, %rdi
    .extern exception_handler
    call exception_handler
1:  hlt
    jmp 1b
.endm

.macro EXC_ERR vec
    .global isr\vec
isr\vec:
    /* CPU pushed an error code on the stack already.
     * Normalize to: [gprs...][vector][err][cpu frame...] */
    pushq $\vec
    PUSH_GPRS
    movq %rsp, %rdi
    .extern exception_handler
    call exception_handler
1:  hlt
    jmp 1b
.endm

.global isr80
isr80:
    /* Save GP registers. */
    PUSH_GPRS

    /* rdi = &regs */
    movq %rsp, %rdi
    .extern syscall_handler
    call syscall_handler

    /* Restore registers and return. */
    POP_GPRS

    iretq

/* Minimal exception handlers (print + halt).
 *  - #DF  (8)  : error code
 *  - #GP  (13) : error code
 *  - #PF  (14) : error code
 *  - #UD  (6)  : no error code (useful when the CPU traps on unsupported instructions)
 */
EXC_NOERR 6
EXC_ERR 8
EXC_ERR 13
EXC_ERR 14

/* PIC IRQs after remap to 0x20-0x2F.
 * These stubs just ACK (EOI) via irq_handler() and return.
 */
.macro IRQ vec
    .global isr\vec
isr\vec:
    PUSH_GPRS
    movl $\vec, %edi
    .extern irq_handler
    call irq_handler
    POP_GPRS
    iretq
.endm

IRQ 32
IRQ 33
IRQ 34
IRQ 35
IRQ 36
IRQ 37
IRQ 38
IRQ 39
IRQ 40
IRQ 41
IRQ 42
IRQ 43
IRQ 44
IRQ 45
IRQ 46
IRQ 47
