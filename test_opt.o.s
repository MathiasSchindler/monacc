.section .text.foo,"ax",@progbits
.globl foo
foo:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %edi, -8(%rbp)
  mov %esi, -16(%rbp)
  mov -8(%rbp), %eax
  add -16(%rbp), %eax
  jmp .Lret0
.Lret0:
  leave
  ret

.section .text.bar,"ax",@progbits
.globl bar
bar:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %edi, -8(%rbp)
  mov %esi, -16(%rbp)
  mov -8(%rbp), %eax
  sub -16(%rbp), %eax
  jmp .Lret1
.Lret1:
  leave
  ret

.section .text.mul,"ax",@progbits
.globl mul
mul:
  push %rbp
  mov %rsp, %rbp
  sub $16, %rsp
  mov %edi, -8(%rbp)
  mov %esi, -16(%rbp)
  mov -8(%rbp), %eax
  imul -16(%rbp), %eax
  jmp .Lret2
.Lret2:
  leave
  ret

