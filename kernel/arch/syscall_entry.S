.section .text
.code64

/* x86_64 SYSCALL entry stub.
 *
 * On entry (from userspace):
 *   rax = syscall number
 *   rdi,rsi,rdx,r10,r8,r9 = args
 *   rcx = user RIP (return address)
 *   r11 = user RFLAGS
 *   rsp = user RSP (SYSCALL does NOT switch stacks)
 */

.global syscall_entry
.extern syscall_handler
.extern syscall_kstack_top
.extern syscall_user_rsp

/* Shared state between C and this entry stub.
 * Defined here (not in C) because monacc currently emits file-scope globals
 * as local symbols in ET_REL, which breaks references from assembly.
 */
.section .bss
.balign 8
.global syscall_kstack_top
syscall_kstack_top:
    .quad 0

.global syscall_user_rsp
syscall_user_rsp:
    .quad 0

.section .text

/* Keep in sync with kernel/main.c struct regs layout and arch/isr.S PUSH_GPRS.
 */
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

syscall_entry:
    /* Save user stack pointer and switch to kernel syscall stack. */
    movq %rsp, syscall_user_rsp(%rip)
    movq syscall_kstack_top(%rip), %rsp

    /* Maintain SysV alignment for the call into C.
     * We push 16 qwords total (1 padding + 15 GPRs) = 128 bytes.
     * If syscall_kstack_top is 16-aligned, %rsp will be 0 mod 16 before call.
     */
    pushq $0
    PUSH_GPRS

    movq %rsp, %rdi
    call syscall_handler

    POP_GPRS
    addq $8, %rsp

    /* Return to userland with IF=0 for now.
     * We don't remap/mask the legacy PIC yet, so allowing interrupts in ring3
     * would deliver IRQs on vectors 0x08-0x0f and collide with exceptions. */
    andq $~(1<<9), %r11

    /* Restore user stack and return to userspace.
     * RCX and R11 were restored from the saved frame.
     */
    movq syscall_user_rsp(%rip), %rsp
    sysretq
