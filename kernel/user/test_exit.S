.section .rodata.userprog,"a"
.global userprog_start
.global userprog_end

userprog_start:
    /* write(1, msg, len) */
    lea msg(%rip), %rsi
    mov $1, %rdi
    mov $1, %rax
    mov $msg_len, %rdx
    int $0x80

    /* exit(42) */
    mov $60, %rax
    mov $42, %rdi
    int $0x80

    hlt
    jmp .

msg:
    .ascii "Hello from userland!\n"
    .set msg_len, . - msg

userprog_end:
