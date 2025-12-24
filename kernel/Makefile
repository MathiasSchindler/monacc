# Phase 2: Multiboot2 + serial I/O + syscalls (read/write/exit)
# Now building with monacc!

ARCH ?= x86_64

# Use monacc for C files, GNU as for assembly
CC := ../bin/monacc
AS ?= as
LD ?= ld

BUILD := build
ISO_DIR := $(BUILD)/iso
KERNEL_ELF := $(BUILD)/kernel.elf
KERNEL_BIN := $(ISO_DIR)/boot/kernel.elf
GRUB_CFG := $(ISO_DIR)/boot/grub/grub.cfg
DEBUGCON_LOG := $(BUILD)/debugcon.log

# Optional initramfs (uncompressed newc cpio). Passed as a Multiboot2 module.
#
# Default: use the current dev initramfs from the repo root `release/` folder
# (created by `scripts/make-distro.sh`). Override or disable as needed:
#   make -C kernel INITRAMFS=../release/monacc-dev-initramfs.cpio run
#   make -C kernel INITRAMFS= run
INITRAMFS_DEFAULT := ../release/monacc-dev-initramfs.cpio
ifneq ($(wildcard $(INITRAMFS_DEFAULT)),)
INITRAMFS ?= $(INITRAMFS_DEFAULT)
else
INITRAMFS ?=
endif
INITRAMFS_ISO := $(ISO_DIR)/boot/initramfs.cpio
INITRAMFS_STAMP := $(BUILD)/.initramfs_path

.PHONY: FORCE
FORCE:

# UEFI firmware (OVMF). Optional: use the `run-uefi-*` targets.
OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_TEMPLATE ?= /usr/share/OVMF/OVMF_VARS_4M.fd
OVMF_VARS := $(BUILD)/ovmf_vars.fd

# Video device for UEFI boot. OVMF typically provides GOP for virtio.
VGA ?= virtio

# monacc flags: just -c and -I include
# Optional debug knobs (passed to C as -D...)
KDEBUG_SYSCALLS ?= 0

CFLAGS := -c -I include -DKDEBUG_SYSCALLS=$(KDEBUG_SYSCALLS)

ASFLAGS := --64

LDFLAGS := -nostdlib -z max-page-size=0x1000 -T link.ld

OBJS := \
	$(BUILD)/boot/multiboot2.o \
	$(BUILD)/main.o \
	$(BUILD)/arch/serial.o \
	$(BUILD)/arch/serial2.o \
	$(BUILD)/arch/except.o \
	$(BUILD)/arch/pic.o \
	$(BUILD)/arch/irq.o \
	$(BUILD)/arch/idt.o \
	$(BUILD)/arch/gdt.o \
	$(BUILD)/arch/syscall.o \
	$(BUILD)/arch/syscall_entry.o \
	$(BUILD)/arch/gdt_reload.o \
	$(BUILD)/arch/isr.o \
	$(BUILD)/arch/lowlevel.o \
	$(BUILD)/boot/mb2.o \
	$(BUILD)/boot/pvh.o \
	$(BUILD)/elf/elf.o \
	$(BUILD)/fs/cpio_newc.o \
	$(BUILD)/fs/vfs.o \
	$(BUILD)/mm/pmm.o \
	$(BUILD)/proc/process.o \
	$(BUILD)/proc/sched.o \
	$(BUILD)/sys/syscalls.o \
	$(BUILD)/sys/utils.o \
	$(BUILD)/net/netproxy.o \
	$(BUILD)/user/test_mmap.o \
	$(BUILD)/user/echo_blob.o

.PHONY: all clean elf iso run run-uefi run-debug logs iso-info

.PHONY: run-pvh

all: iso

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/boot:
	mkdir -p $(BUILD)/boot

$(BUILD)/fs:
	mkdir -p $(BUILD)/fs

$(BUILD)/arch:
	mkdir -p $(BUILD)/arch

$(BUILD)/mm:
	mkdir -p $(BUILD)/mm

$(BUILD)/proc:
	mkdir -p $(BUILD)/proc

$(BUILD)/sys:
	mkdir -p $(BUILD)/sys

$(BUILD)/boot/multiboot2.o: boot/multiboot2.S | $(BUILD)/boot
	$(AS) $(ASFLAGS) -o $@ $<

$(BUILD)/boot/mb2.o: boot/mb2.c include/kernel.h | $(BUILD)/boot
	$(CC) $(CFLAGS) boot/mb2.c -o $@

$(BUILD)/boot/pvh.o: boot/pvh.c include/kernel.h | $(BUILD)/boot
	$(CC) $(CFLAGS) boot/pvh.c -o $@

$(BUILD)/main.o: main.c include/kernel.h include/proc.h include/fs.h include/sys.h | $(BUILD)
	$(CC) $(CFLAGS) main.c -o $@

$(BUILD)/arch/serial.o: arch/serial.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/serial.c -o $@

$(BUILD)/arch/serial2.o: arch/serial2.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/serial2.c -o $@

$(BUILD)/arch/except.o: arch/except.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/except.c -o $@

$(BUILD)/arch/pic.o: arch/pic.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/pic.c -o $@

$(BUILD)/arch/irq.o: arch/irq.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/irq.c -o $@

$(BUILD)/arch/idt.o: arch/idt.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/idt.c -o $@

$(BUILD)/arch/gdt.o: arch/gdt.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/gdt.c -o $@

$(BUILD)/arch/syscall.o: arch/syscall.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/syscall.c -o $@

$(BUILD)/arch/isr.o: arch/isr.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/isr.S

$(BUILD)/arch/syscall_entry.o: arch/syscall_entry.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/syscall_entry.S

$(BUILD)/arch/lowlevel.o: arch/lowlevel.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/lowlevel.S

$(BUILD)/arch/gdt_reload.o: arch/gdt_reload.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/gdt_reload.S

$(BUILD)/elf:
	mkdir -p $(BUILD)/elf

$(BUILD)/elf/elf.o: elf/elf.c include/kernel.h | $(BUILD)/elf
	$(CC) $(CFLAGS) elf/elf.c -o $@

$(BUILD)/fs/cpio_newc.o: fs/cpio_newc.c include/kernel.h | $(BUILD)/fs
	$(CC) $(CFLAGS) fs/cpio_newc.c -o $@

$(BUILD)/fs/vfs.o: fs/vfs.c include/kernel.h include/fs.h include/proc.h include/sys.h | $(BUILD)/fs
	$(CC) $(CFLAGS) fs/vfs.c -o $@

$(BUILD)/mm/pmm.o: mm/pmm.c include/kernel.h | $(BUILD)/mm
	$(CC) $(CFLAGS) mm/pmm.c -o $@

$(BUILD)/proc/process.o: proc/process.c include/kernel.h include/proc.h include/fs.h include/sys.h | $(BUILD)/proc
	$(CC) $(CFLAGS) proc/process.c -o $@

$(BUILD)/proc/sched.o: proc/sched.c include/kernel.h include/proc.h include/sys.h | $(BUILD)/proc
	$(CC) $(CFLAGS) proc/sched.c -o $@

$(BUILD)/sys/syscalls.o: sys/syscalls.c include/kernel.h include/proc.h include/fs.h include/sys.h include/net.h | $(BUILD)/sys
	$(CC) $(CFLAGS) sys/syscalls.c -o $@

$(BUILD)/sys/utils.o: sys/utils.c include/kernel.h include/sys.h include/proc.h | $(BUILD)/sys
	$(CC) $(CFLAGS) sys/utils.c -o $@

$(BUILD)/net:
	mkdir -p $(BUILD)/net

$(BUILD)/net/netproxy.o: net/netproxy.c include/kernel.h include/net.h | $(BUILD)/net
	$(CC) $(CFLAGS) net/netproxy.c -o $@

$(BUILD)/user:
	mkdir -p $(BUILD)/user

$(BUILD)/user/test_mmap.o: user/test_mmap.S | $(BUILD)/user
	$(AS) $(ASFLAGS) -o $@ user/test_mmap.S

$(BUILD)/user/echo_blob.o: user/echo_blob.S ../bin/echo | $(BUILD)/user
	$(AS) $(ASFLAGS) -o $@ user/echo_blob.S

elf: $(KERNEL_ELF)

$(KERNEL_ELF): $(OBJS) link.ld | $(BUILD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

$(INITRAMFS_STAMP): FORCE | $(BUILD)
	@{ \
		printf '%s' "$(INITRAMFS)" > $@.tmp; \
		if [ ! -f $@ ] || ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm -f $@.tmp; fi; \
	}

$(GRUB_CFG): $(INITRAMFS_STAMP) | $(ISO_DIR)/boot/grub
	{ \
		printf '%s\n' \
		'insmod serial' \
		'insmod terminal_serial' \
		'insmod multiboot2' \
		'serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1' \
		'terminal_input serial' \
		'terminal_output serial' \
		'' \
		'echo "[grub] loaded grub.cfg"' \
		'echo "[grub] booting kernel..."' \
		'multiboot2 /boot/kernel.elf'; \
		if [ -n "$(INITRAMFS)" ]; then \
			printf '%s\n' 'module2 /boot/initramfs.cpio initramfs'; \
		fi; \
		printf '%s\n' 'boot'; \
	} > $@

$(ISO_DIR)/boot/grub:
	mkdir -p $@

$(KERNEL_BIN): $(KERNEL_ELF) | $(ISO_DIR)/boot
	cp $(KERNEL_ELF) $@

ifneq ($(strip $(INITRAMFS)),)
$(INITRAMFS_ISO): $(INITRAMFS) | $(ISO_DIR)/boot
	cp $(INITRAMFS) $@
endif

$(ISO_DIR)/boot:
	mkdir -p $@

iso: $(BUILD)/kernel.iso

ISO_DEPS := $(KERNEL_BIN) $(GRUB_CFG)
ifneq ($(strip $(INITRAMFS)),)
ISO_DEPS += $(INITRAMFS_ISO)
endif

$(BUILD)/kernel.iso: $(ISO_DEPS)
	grub-mkrescue -o $@ $(ISO_DIR) >/dev/null

$(OVMF_VARS):
	mkdir -p $(BUILD)
	cp $(OVMF_VARS_TEMPLATE) $@



# === Run targets (kept intentionally small) ===
#
# Targets:
#   make run                 # BIOS/SeaBIOS, serial on stdio (default, headless)
#   make run GUI=1           # BIOS/SeaBIOS, GUI
#   make run-uefi            # UEFI/OVMF, serial on stdio (headless)
#   make run-uefi GUI=1      # UEFI/OVMF, GUI
#   make run-debug           # UEFI/OVMF, debugcon log at build/debugcon.log

QEMU ?= qemu-system-x86_64
GUI ?= 0
QEMU_LOG ?= $(BUILD)/qemu.log

QEMU_COMMON := -cdrom $(BUILD)/kernel.iso -serial stdio -device isa-debug-exit,iobase=0xf4,iosize=0x04

ifeq ($(GUI),0)
QEMU_COMMON += -display none -monitor none -no-reboot
else
QEMU_COMMON += -no-reboot
endif

.PHONY: run run-uefi

.PHONY: run-log run-gdbstub gdb

.PHONY: run-net

# Default run target: boot with SeaBIOS (simplest for serial bring-up).
run: iso
	$(QEMU) $(QEMU_COMMON) || [ $$? -eq 33 ]

# Run with host-proxy networking over COM2.
# This enables IPv6-only net tools (dns6/tcp6/wget6/ntp6/...) without a full in-kernel TCP/IP stack.
NETPROXY_SOCK ?= $(BUILD)/netproxy.sock

run-net: iso
	rm -f $(NETPROXY_SOCK)
	@echo "==> starting host netproxy (COM2)"
	@bash -c ' \
		set -e; \
		sock="$(NETPROXY_SOCK)"; \
		python3 tools/netproxy.py "$$sock" & \
		pid=$$!; \
		trap "kill $$pid 2>/dev/null || true" EXIT; \
		$(QEMU) $(QEMU_COMMON) -serial unix:$(NETPROXY_SOCK),server,nowait; \
		st=$$?; \
		if [ $$st -ne 33 ]; then exit $$st; fi; \
	'

# Same as `run`, but also logs QEMU debug output to $(QEMU_LOG).
# Useful when the VM resets/triple-faults before printing anything.
run-log: iso
	rm -f $(QEMU_LOG)
	$(QEMU) $(QEMU_COMMON) -d int,cpu_reset -D $(QEMU_LOG) || [ $$? -eq 33 ]
	@echo "Wrote $(QEMU_LOG)"

# Direct PVH boot (no ISO/GRUB): requires PVH ELF note in kernel.elf.
# INITRAMFS is optional; if set, it is passed via -initrd and appears as a PVH module.
run-pvh: elf
	@{ \
		initrd=""; \
		if [ -n "$(INITRAMFS)" ]; then initrd="-initrd $(INITRAMFS)"; fi; \
		$(QEMU) -kernel $(KERNEL_ELF) $$initrd -serial stdio -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
			$$( [ "$(GUI)" = "0" ] && printf '%s' '-display none -monitor none -no-reboot' || true ); \
	} || [ $$? -eq 33 ]

# Start QEMU halted with a GDB server on :1234 (useful for early boot debugging).
run-gdbstub: iso
	@echo "==> QEMU waiting for GDB on :1234"
	$(QEMU) $(QEMU_COMMON) -s -S || [ $$? -eq 33 ]

# Convenience: attach gdb to a `run-gdbstub` session.
gdb: elf
	@gdb $(KERNEL_ELF) -ex 'target remote :1234'

# UEFI/OVMF run (optional).
run-uefi: iso $(OVMF_VARS)
	$(QEMU) \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,format=raw,file=$(OVMF_VARS) \
		-vga $(VGA) \
		$(QEMU_COMMON) || [ $$? -eq 33 ]

.PHONY: run-debug

run-debug: iso $(OVMF_VARS)
	rm -f $(DEBUGCON_LOG)
	qemu-system-x86_64 \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,format=raw,file=$(OVMF_VARS) \
		-vga $(VGA) \
		-cdrom $(BUILD)/kernel.iso -display none \
		-monitor none \
		-serial stdio \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 \
		-debugcon file:$(DEBUGCON_LOG) -global isa-debugcon.iobase=0xe9

.PHONY: logs

logs:
	@echo "--- debugcon ($(DEBUGCON_LOG)) ---"
	@([ -f $(DEBUGCON_LOG) ] && (wc -c $(DEBUGCON_LOG); hexdump -C $(DEBUGCON_LOG) | head -n 40) ) || echo "(no debugcon log yet)"

.PHONY: iso-info

iso-info: iso
	@echo "--- El Torito boot images (build/kernel.iso) ---"
	@xorriso -indev $(BUILD)/kernel.iso -report_el_torito plain | sed -n '1,120p'

clean:
	rm -rf $(BUILD)
