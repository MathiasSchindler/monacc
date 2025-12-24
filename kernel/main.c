#include "kernel.h"
#include "proc.h"
#include "fs.h"
#include "sys.h"

/* External functions from other modules */
void serial_init(void);
void serial_write(const char *s);
void gdt_tss_init(void);
void tss_load(void);
void idt_init(void);
void syscall_init(void);
void pic_init(void);
void enter_user(uint64_t entry, uint64_t sp);

/* Embedded monacc-built ELF tools (from user/*.S incbin). */
extern void user_elf_echo_start(void);
extern void user_elf_echo_end(void);

__attribute__((noreturn)) void kmain(void) {
	serial_init();
	serial_write("monacc kernel\n");

	/* Initialize physical memory manager */
	serial_write("[k] pmm_init...\n");
	pmm_init();
	serial_write("[k] pmm_init ok\n");

	/* Reserve the fixed virtual user stack region so it is never handed out by
	 * the PMM allocator (kernel stacks, image backups, etc).
	 */
	(void)pmm_reserve_pages(USER_STACK_BASE, (uint32_t)USER_STACK_PAGES);

	/* Set up GDT (with ring-3 segments) + TSS, then IDT with int 0x80 gate. */
	serial_write("[k] gdt_tss_init...\n");
	gdt_tss_init();
	serial_write("[k] gdt_tss_init ok\n");
	serial_write("[k] idt_init...\n");
	idt_init();
	serial_write("[k] idt_init ok\n");

	/* Remap PIC away from exception vectors and mask all IRQs.
	 * This makes it safe to run ring3 with IF=1 even before a full IRQ subsystem exists.
	 */
	serial_write("[k] pic_init...\n");
	pic_init();
	serial_write("[k] pic_init ok\n");

	serial_write("[k] tss_load...\n");
	tss_load();
	serial_write("[k] tss_load ok\n");

	serial_write("[k] syscall_init...\n");
	syscall_init();
	serial_write("[k] syscall_init ok\n");

	/* Load and run a real monacc-built ELF tool (embedded as bytes). */
	{
		const uint8_t *imgp = (const uint8_t *)user_elf_echo_start;
		uint64_t img_sz = (uint64_t)user_elf_echo_end - (uint64_t)user_elf_echo_start;
		const char *boot_arg0 = "echo";
		const char *boot_arg1 = "hello";
		uint64_t boot_argc = 2;

		/* If GRUB provided an initramfs module, prefer loading /bin/echo from it. */
		uint64_t mod_start = 0, mod_end = 0;
		int have_mod = 0;
		if (pvh_find_first_module(pvh_start_info_ptr, &mod_start, &mod_end) == 0) {
			serial_write("[k] found pvh module\n");
			have_mod = 1;
		} else if (mb2_find_first_module(mb2_info_ptr, &mod_start, &mod_end) == 0) {
			serial_write("[k] found multiboot2 module\n");
			have_mod = 1;
		}
		if (have_mod) {
			g_initramfs = (const uint8_t *)mod_start;
			g_initramfs_sz = mod_end - mod_start;
			if (mod_end > mod_start) {
				uint64_t m_start = mod_start & ~(uint64_t)(PAGE_SIZE - 1);
				uint64_t m_end = (mod_end + (PAGE_SIZE - 1)) & ~(uint64_t)(PAGE_SIZE - 1);
				if (m_end > m_start && m_start >= 0x400000) {
					(void)pmm_reserve_pages(m_start, (uint32_t)((m_end - m_start) / PAGE_SIZE));
				}
			}
			const uint8_t *f = 0;
			uint64_t fsz = 0;
			if (cpio_newc_find((const uint8_t *)mod_start, mod_end - mod_start, "init", &f, &fsz) == 0) {
				serial_write("[k] initramfs: using /init\n");
				imgp = f;
				img_sz = fsz;
				boot_arg0 = "/init";
				boot_arg1 = 0;
				boot_argc = 1;
			} else if (cpio_newc_find((const uint8_t *)mod_start, mod_end - mod_start, "bin/echo", &f, &fsz) == 0) {
				serial_write("[k] initramfs: /init not found; using bin/echo\n");
				imgp = f;
				img_sz = fsz;
				boot_arg0 = "/bin/echo";
				boot_arg1 = "hello";
				boot_argc = 2;
			} else {
				serial_write("[k] initramfs: init and bin/echo not found; using embedded\n");
			}
		}
		uint64_t user_entry = 0;
		uint64_t brk_init = 0;

		serial_write("[k] elf_load_exec(echo)...\n");
		if (elf_load_exec(imgp, img_sz, &user_entry, &brk_init) != 0) {
			serial_write("[k] elf_load_exec failed\n");
			halt_forever();
		}
		serial_write("[k] elf_load_exec ok\n");

		/* Establish the initial process (PID 1) before entering userland, so
		 * fork()/wait()/pipes have valid per-proc bookkeeping from the start.
		 */
		if (!g_cur) {
			struct kproc *initp = kproc_alloc(0);
			if (!initp) {
				serial_write("[k] kproc_alloc(init) failed\n");
				halt_forever();
			}
			g_cur = initp;
			g_cur->img_base = USER_IMG_BASE;
			g_cur->img_end = brk_init;
			if (kproc_ensure_img_backup(g_cur, brk_init) != 0) {
				serial_write("[k] kproc_ensure_img_backup(init) failed\n");
				halt_forever();
			}
			syscall_kstack_top = g_cur->kstack_base + (uint64_t)g_cur->kstack_pages * PAGE_SIZE;
			kproc_img_save(g_cur);
		}

		/* Allocate the init process's stack backup buffer and build the initial
		 * user stack in the fixed USER_STACK_BASE..USER_STACK_TOP region.
		 */
		if (g_cur && !g_cur->user_stack_base) {
			uint64_t buf = pmm_alloc_pages_high((uint32_t)USER_STACK_PAGES);
			if (buf == 0) {
				serial_write("[k] no memory for user stack backup\n");
				halt_forever();
			}
			g_cur->user_stack_base = buf;
			g_cur->user_stack_pages = (uint32_t)USER_STACK_PAGES;
		}
		uint64_t sp = align_down_u64(USER_STACK_TOP, 16);

		/* Copy argument strings into user stack memory. */
		uint64_t u_arg0 = 0;
		uint64_t u_arg1 = 0;
		uint64_t arg0_len = kstrnlen(boot_arg0, KEXEC_MAX_STR);
		sp = user_stack_push_bytes(sp, boot_arg0, arg0_len + 1);
		u_arg0 = sp;
		if (boot_argc > 1 && boot_arg1) {
			uint64_t arg1_len = kstrnlen(boot_arg1, KEXEC_MAX_STR);
			sp = user_stack_push_bytes(sp, boot_arg1, arg1_len + 1);
			u_arg1 = sp;
		}

		/* Align before pushing pointers. */
		sp = align_down_u64(sp, 16);

		/* auxv terminator: AT_NULL (0), 0 */
		sp = user_stack_push_u64(sp, 0);
		sp = user_stack_push_u64(sp, 0);
		/* envp terminator */
		sp = user_stack_push_u64(sp, 0);
		/* argv terminator */
		sp = user_stack_push_u64(sp, 0);
		/* argv pointers */
		if (boot_argc > 1 && u_arg1) {
			sp = user_stack_push_u64(sp, u_arg1);
		}
		sp = user_stack_push_u64(sp, u_arg0);
		/* argc */
		sp = user_stack_push_u64(sp, boot_argc);

		serial_write("Entering userland...\n");
		if (g_cur) {
			g_cur->user_rsp = sp;
			syscall_user_rsp = sp;
			kproc_stack_save(g_cur);
		}
		enter_user(user_entry, sp);
	}

	halt_forever();
}
