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

# UEFI firmware (OVMF). Optional: use the `run-uefi-*` targets.
OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS_TEMPLATE ?= /usr/share/OVMF/OVMF_VARS_4M.fd
OVMF_VARS := $(BUILD)/ovmf_vars.fd

# Video device for UEFI boot. OVMF typically provides GOP for virtio.
VGA ?= virtio

# monacc flags: just -c and -I include
CFLAGS := -c -I include

ASFLAGS := --64

LDFLAGS := -nostdlib -z max-page-size=0x1000 -T link.ld

OBJS := \
	$(BUILD)/boot/multiboot2.o \
	$(BUILD)/main.o \
	$(BUILD)/arch/serial.o \
	$(BUILD)/arch/except.o \
	$(BUILD)/arch/idt.o \
	$(BUILD)/arch/gdt.o \
	$(BUILD)/arch/gdt_reload.o \
	$(BUILD)/arch/isr.o \
	$(BUILD)/arch/lowlevel.o \
	$(BUILD)/mm/pmm.o \
	$(BUILD)/user/test_mmap.o

.PHONY: all clean iso run elf

all: iso

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/boot:
	mkdir -p $(BUILD)/boot

$(BUILD)/arch:
	mkdir -p $(BUILD)/arch

$(BUILD)/boot/multiboot2.o: boot/multiboot2.S | $(BUILD)/boot
	$(AS) $(ASFLAGS) -o $@ $<

$(BUILD)/main.o: main.c include/kernel.h | $(BUILD)
	$(CC) $(CFLAGS) main.c -o $@

$(BUILD)/arch/serial.o: arch/serial.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/serial.c -o $@

$(BUILD)/arch/except.o: arch/except.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/except.c -o $@

$(BUILD)/arch/idt.o: arch/idt.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/idt.c -o $@

$(BUILD)/arch/gdt.o: arch/gdt.c include/kernel.h | $(BUILD)/arch
	$(CC) $(CFLAGS) arch/gdt.c -o $@

$(BUILD)/arch/isr.o: arch/isr.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/isr.S

$(BUILD)/arch/lowlevel.o: arch/lowlevel.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/lowlevel.S

$(BUILD)/arch/gdt_reload.o: arch/gdt_reload.S | $(BUILD)/arch
	$(AS) $(ASFLAGS) -o $@ arch/gdt_reload.S

$(BUILD)/mm:
	mkdir -p $(BUILD)/mm

$(BUILD)/mm/pmm.o: mm/pmm.c include/kernel.h | $(BUILD)/mm
	$(CC) $(CFLAGS) mm/pmm.c -o $@

$(BUILD)/user:
	mkdir -p $(BUILD)/user

$(BUILD)/user/test_mmap.o: user/test_mmap.S | $(BUILD)/user
	$(AS) $(ASFLAGS) -o $@ user/test_mmap.S

elf: $(KERNEL_ELF)

$(KERNEL_ELF): $(OBJS) link.ld | $(BUILD)
	$(LD) $(LDFLAGS) -o $@ $(OBJS)

$(GRUB_CFG): | $(ISO_DIR)/boot/grub
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
		'multiboot2 /boot/kernel.elf' \
		'boot' > $@

$(ISO_DIR)/boot/grub:
	mkdir -p $@

$(KERNEL_BIN): $(KERNEL_ELF) | $(ISO_DIR)/boot
	cp $(KERNEL_ELF) $@

$(ISO_DIR)/boot:
	mkdir -p $@

iso: $(BUILD)/kernel.iso

$(BUILD)/kernel.iso: $(KERNEL_BIN) $(GRUB_CFG)
	grub-mkrescue -o $@ $(ISO_DIR) >/dev/null

$(OVMF_VARS):
	mkdir -p $(BUILD)
	cp $(OVMF_VARS_TEMPLATE) $@


.PHONY: run-gui run-serial run-bios-gui run-bios-serial run-uefi-gui run-uefi-serial

# Default run targets boot with SeaBIOS (simplest for serial bring-up).
run: run-bios-serial
run-gui: run-bios-gui
run-serial: run-bios-serial

# SeaBIOS-based runs.
run-bios-gui: iso
	qemu-system-x86_64 -cdrom $(BUILD)/kernel.iso -serial stdio \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 || [ $$? -eq 33 ]

run-bios-serial: iso
	qemu-system-x86_64 -cdrom $(BUILD)/kernel.iso -display none \
		-monitor none \
		-serial stdio \
		-no-reboot \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 || [ $$? -eq 33 ]

.PHONY: run-bios-serial-log

run-bios-serial-log: iso
	rm -f $(BUILD)/qemu.log
	qemu-system-x86_64 -cdrom $(BUILD)/kernel.iso -display none \
		-monitor none \
		-serial stdio \
		-no-reboot \
		-d int,cpu_reset,guest_errors -D $(BUILD)/qemu.log \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 || [ $$? -eq 33 ]

# UEFI/OVMF runs (optional).
run-uefi-gui: iso $(OVMF_VARS)
	qemu-system-x86_64 \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,format=raw,file=$(OVMF_VARS) \
		-vga $(VGA) \
		-cdrom $(BUILD)/kernel.iso -serial stdio \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 || [ $$? -eq 33 ]

run-uefi-serial: iso $(OVMF_VARS)
	qemu-system-x86_64 \
		-drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,format=raw,file=$(OVMF_VARS) \
		-vga $(VGA) \
		-cdrom $(BUILD)/kernel.iso -display none \
		-monitor none \
		-serial stdio \
		-device isa-debug-exit,iobase=0xf4,iosize=0x04 || [ $$? -eq 33 ]

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
