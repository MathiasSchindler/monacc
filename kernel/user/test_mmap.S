/* Test program that uses mmap to allocate memory and write to it.
 * If mmap works, we write a message and exit 0.
 * If mmap fails, we exit with code 1.
 */

.section .rodata.userprog,"a"
.global userprog_start
.global userprog_end
/* Also export as function symbols for monacc compatibility */
.global userprog_start_func
.global userprog_end_func

userprog_start:
userprog_start_func:
	/* Debug: print "A" to show we started */
	mov $1, %rax           /* write */
	mov $1, %rdi           /* stdout */
	lea msg_start(%rip), %rsi
	mov $2, %rdx           /* count */
	int $0x80

	/* mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) */
	/* syscall 9: rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=offset */
	mov $9, %rax           /* mmap */
	xor %rdi, %rdi         /* addr = NULL */
	mov $4096, %rsi        /* len = 4096 (one page) */
	mov $0x3, %rdx         /* prot = PROT_READ | PROT_WRITE */
	mov $0x22, %r10        /* flags = MAP_PRIVATE | MAP_ANONYMOUS */
	mov $-1, %r8           /* fd = -1 */
	xor %r9, %r9           /* offset = 0 */
	int $0x80

	/* Check if mmap failed (negative return = error) */
	test %rax, %rax
	js mmap_failed

	/* mmap succeeded, rax = pointer to memory */
	mov %rax, %r12         /* Save pointer in r12 */

	/* Write a test pattern to allocated memory */
	movb $0x42, (%r12)     /* Write 'B' */
	movb $0x43, 1(%r12)    /* Write 'C' */
	
	/* Read back and verify */
	cmpb $0x42, (%r12)
	jne verify_failed
	cmpb $0x43, 1(%r12)
	jne verify_failed

	/* Write success message: "mmap ok\n" */
	mov $1, %rax           /* write */
	mov $1, %rdi           /* stdout */
	lea msg_ok(%rip), %rsi /* buf */
	mov $8, %rdx           /* count */
	int $0x80

	/* munmap the page */
	mov $11, %rax          /* munmap */
	mov %r12, %rdi         /* addr */
	mov $4096, %rsi        /* len */
	int $0x80

	/* exit(0) - success */
	mov $60, %rax
	xor %rdi, %rdi
	int $0x80

mmap_failed:
	/* Write failure message: "mmap fail\n" */
	mov $1, %rax
	mov $1, %rdi
	lea msg_fail(%rip), %rsi
	mov $10, %rdx
	int $0x80

	/* exit(1) */
	mov $60, %rax
	mov $1, %rdi
	int $0x80

verify_failed:
	/* Write verify failure: "verify fail\n" */
	mov $1, %rax
	mov $1, %rdi
	lea msg_vfail(%rip), %rsi
	mov $12, %rdx
	int $0x80

	/* exit(2) */
	mov $60, %rax
	mov $2, %rdi
	int $0x80

msg_start:
	.ascii "A\n"
msg_ok:
	.ascii "mmap ok\n"
msg_fail:
	.ascii "mmap fail\n"
msg_vfail:
	.ascii "verify fail\n"

userprog_end:
userprog_end_func:
