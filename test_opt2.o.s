.section .text.add_chars,"ax",@progbits
.globl add_chars
add_chars:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %dil, -8(%rbp)
  mov %sil, -16(%rbp)
  movzb -8(%rbp), %eax
  movzb -16(%rbp), %ecx
  add %ecx, %eax
  jmp .Lret0
.Lret0:
  leave
  ret

.section .text.ptr_add,"ax",@progbits
.globl ptr_add
ptr_add:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %rdi, -8(%rbp)
  mov %esi, -16(%rbp)
  mov -8(%rbp), %rax
  push %rax
  mov -16(%rbp), %eax
  pop %rcx
  cdqe
  imul $4, %rax
  add %rcx, %rax
  jmp .Lret1
.Lret1:
  leave
  ret

