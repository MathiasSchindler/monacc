# monacc unified build
#
# Usage:
#   make        # Build compiler + all 70 tools
#   make test   # Build everything + run all tests
#   make clean  # Remove build artifacts

CC ?= cc
MONACC := bin/monacc

# Use the internal ELF object emitter by default (replaces external `as`).
# Set EMITOBJ=0 to force using the system assembler instead.
EMITOBJ ?= 1
ifeq ($(EMITOBJ),1)
MONACC_EMITOBJ_FLAG := --emit-obj
else
MONACC_EMITOBJ_FLAG :=
endif

# Build configuration
DEBUG ?= 0
LTO ?= 1
MULTI ?= 0

# Optional compiler probes.
# Note: the emit-obj probe is enabled by default and is treated as a normal test.
SELFTEST ?= 0
SELFTEST_EMITOBJ ?= 1
SELFTEST_ELFREAD ?= 1
SELFTEST_LINKINT ?= 1

CFLAGS_BASE := -Wall -Wextra -Wpedantic -fno-stack-protector
ifeq ($(DEBUG),1)
CFLAGS := -O0 -g $(CFLAGS_BASE)
LDFLAGS :=
else
CFLAGS := -Os -DNDEBUG $(CFLAGS_BASE) -ffunction-sections -fdata-sections \
	-fno-unwind-tables -fno-asynchronous-unwind-tables
LDFLAGS := -s -Wl,--gc-sections
endif

ifeq ($(LTO),1)
CFLAGS += -flto
LDFLAGS += -flto
endif


# Core sources
CORE_COMMON_SRC := \
	core/mc_str.c \
	core/mc_fmt.c \
	core/mc_snprint.c \
	core/mc_libc_compat.c \
	core/mc_start_env.c \
	core/mc_io.c \
	core/mc_regex.c

# Hosted-only core sources (not built into MONACC tools)
CORE_HOSTED_SRC := \
	core/mc_start.c


CORE_TOOL_SRC := $(CORE_COMMON_SRC)
CORE_COMPILER_SRC := $(CORE_COMMON_SRC) $(CORE_HOSTED_SRC)

COMPILER_SRC := \
	compiler/monacc_front.c \
	compiler/monacc_fmt.c \
	compiler/monacc_elfread.c \
	compiler/monacc_link.c \
	compiler/monacc_elfobj.c \
	compiler/monacc_sys.c \
	compiler/monacc_ast.c \
	compiler/monacc_parse.c \
	compiler/monacc_str.c \
	compiler/monacc_codegen.c \
	compiler/monacc_pp.c \
	compiler/monacc_main.c \
	$(CORE_COMPILER_SRC)

START_LDFLAGS := -nostartfiles -Wl,-e,_start

# Tool sources (all .c files in tools/)
TOOL_SRCS := $(wildcard tools/*.c)
TOOL_NAMES := $(basename $(notdir $(TOOL_SRCS)))
TOOL_BINS := $(addprefix bin/,$(TOOL_NAMES))
TOOL_BINS_LD := $(addprefix bin/ld/,$(TOOL_NAMES))
TOOL_BINS_INTERNAL := $(addprefix bin/internal/,$(TOOL_NAMES))

# Examples to test (must return exit code 42)
EXAMPLES := hello loop pp ptr charlit strlit sizeof struct proto typedef \
	typedef_multi enum enum_constexpr struct_array fnptr_member ternary \
	cast cast_void logical bitwise_or_xor hex_macro call7 struct_copy \
	array_constexpr prefix_incdec compound_literal postinc_member_array sret_cond \
	unsigned_divmod_pow2 const_index sizeof_array packed_struct compound_literal_assign_global extern_incomplete_array static_local_array static_local_init \
	global_array_store \
	addr_deref_syscall \
	asm_syscall

# Default goal: build everything
.DEFAULT_GOAL := all

.PHONY: all all-split tools-ld tools-internal test clean debug selfhost

# === Initramfs image (for booting sysbox) ===

INITRAMFS_DIR := build/initramfs
INITRAMFS_ROOT := $(INITRAMFS_DIR)/root
INITRAMFS_CPIO := $(INITRAMFS_DIR)/sysbox.cpio
INITRAMFS_GZ := $(INITRAMFS_CPIO).gz

.PHONY: initramfs initramfs-cpio initramfs-root

all: $(MONACC) $(TOOL_BINS) bin/realpath bin/[
	@echo ""
	@echo "Build complete: bin/monacc + $(words $(TOOL_BINS)) tools + aliases"

# Optional split build: build tools twice, once linked via external ld and once via
# the internal linker. This is useful for comparison/bring-up.
all-split: $(MONACC) tools-ld tools-internal
	@echo ""
	@echo "Split build complete: bin/ld/* (external ld) + bin/internal/* (internal linker)"

# === Self-hosting probe: build compiler with monacc ===

MONACC_SELF := bin/monacc-self
# monacc emits _start only for the first input file. Ensure that translation unit
# contains main(), otherwise the produced binary will be a trivial exit stub.
COMPILER_SELFHOST_SRC := \
	compiler/monacc_main.c \
	$(filter-out core/mc_start.c core/mc_vsnprintf.c compiler/monacc_elfobj.c compiler/monacc_main.c,$(COMPILER_SRC))

selfhost: $(MONACC_SELF)
	@echo ""
	@echo "Self-host build complete: $(MONACC_SELF)"

$(MONACC_SELF): $(COMPILER_SELFHOST_SRC) $(MONACC) | bin
	@echo "==> Building self-hosted compiler"
	@$(MONACC) $(MONACC_EMITOBJ_FLAG) -DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

# Stage a minimal rootfs:
# - /init is PID 1 (copied from bin/init)
# - /bin contains all tools (including sh)
# - empty /dev,/proc,/sys mountpoints
initramfs-root: all
	@echo "==> Staging initramfs rootfs"
	@rm -rf $(INITRAMFS_ROOT)
	@mkdir -p $(INITRAMFS_ROOT)/bin $(INITRAMFS_ROOT)/dev $(INITRAMFS_ROOT)/proc $(INITRAMFS_ROOT)/sys
	@cp -a bin/* $(INITRAMFS_ROOT)/bin/
	@cp -a $(INITRAMFS_ROOT)/bin/init $(INITRAMFS_ROOT)/init

# Create an uncompressed newc cpio (useful for debugging).
initramfs-cpio: initramfs-root
	@echo "==> Packing initramfs (newc cpio)"
	@command -v cpio >/dev/null 2>&1 || (echo "error: cpio not found" && exit 1)
	@mkdir -p $(INITRAMFS_DIR)
	@cd $(INITRAMFS_ROOT) && find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 > ../$(notdir $(INITRAMFS_CPIO))
	@echo "Wrote $(INITRAMFS_CPIO)"

# Default initramfs target: gzip-compressed cpio.
initramfs: initramfs-cpio
	@echo "==> Compressing initramfs"
	@command -v gzip >/dev/null 2>&1 || (echo "error: gzip not found" && exit 1)
	@gzip -n -9 -c $(INITRAMFS_CPIO) > $(INITRAMFS_GZ)
	@echo "Wrote $(INITRAMFS_GZ)"

# === Phase 0: Build the compiler with host CC ===

$(MONACC): $(COMPILER_SRC) | bin
	@echo "==> Building compiler"
	$(CC) $(CFLAGS) -I core $(LDFLAGS) $(START_LDFLAGS) $(COMPILER_SRC) -o $@

bin:
	mkdir -p bin

bin/ld:
	mkdir -p bin/ld

bin/internal:
	mkdir -p bin/internal

# === Phase 1: Build tools with monacc ===

bin/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin
	@echo "  $*"
	@$(MONACC) $(MONACC_EMITOBJ_FLAG) -I core $< $(CORE_TOOL_SRC) -o $@

# External-ld linked toolset (kept separate for comparison)
bin/ld/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin/ld
	@echo "  ld/$*"
	@$(MONACC) $(MONACC_EMITOBJ_FLAG) -I core $< $(CORE_TOOL_SRC) -o $@

# Internal-linker toolset
bin/internal/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin/internal
	@echo "  internal/$*"
	@$(MONACC) $(MONACC_EMITOBJ_FLAG) --link-internal -I core $< $(CORE_TOOL_SRC) -o $@

# Print a header before building tools
$(TOOL_BINS): | tool-header
.PHONY: tool-header
tool-header: $(MONACC)
	@echo "==> Building tools with monacc"

$(TOOL_BINS_LD): | tool-header-ld
$(TOOL_BINS_INTERNAL): | tool-header-internal

.PHONY: tool-header-ld tool-header-internal
tool-header-ld: $(MONACC)
	@echo "==> Building tools with monacc (external ld)"

tool-header-internal: $(MONACC)
	@echo "==> Building tools with monacc (internal linker)"

tools-ld: $(TOOL_BINS_LD) bin/ld/realpath bin/ld/[

tools-internal: $(TOOL_BINS_INTERNAL) bin/internal/realpath bin/internal/[

# Tool aliases (readlink serves as realpath, test serves as [)
bin/realpath: bin/readlink
	@cp $< $@

bin/[: bin/test
	@cp $< $@

bin/ld/realpath: bin/ld/readlink | bin/ld
	@cp $< $@

bin/ld/[: bin/ld/test | bin/ld
	@cp $< $@

bin/internal/realpath: bin/internal/readlink | bin/internal
	@cp $< $@

bin/internal/[: bin/internal/test | bin/internal
	@cp $< $@

# === Testing ===

test: all
	@echo ""
	@echo "==> Testing examples"
	@mkdir -p build/test
	@ok=0; fail=0; \
	elfread_rc=0; \
	linkint_rc=0; \
	emitobj_rc=0; \
	matrix_rc=0; \
	for ex in $(EXAMPLES); do \
		$(MONACC) $(MONACC_EMITOBJ_FLAG) examples/$$ex.c -o build/test/$$ex 2>/dev/null && \
		./build/test/$$ex >/dev/null 2>&1; \
		if [ $$? -eq 42 ]; then \
			echo "  ok: $$ex"; \
			ok=$$((ok + 1)); \
		else \
			echo "  FAIL: $$ex"; \
			fail=$$((fail + 1)); \
		fi; \
	done; \
	echo ""; \
	echo "==> Testing tools"; \
	SB_TEST_BIN="$$(pwd)/bin" sh tests/tools/run.sh; \
	tool_rc=$$?; \
	echo ""; \
	if [ "$(SELFTEST_ELFREAD)" = "1" ]; then \
		echo "==> Probe: ELF ET_REL reader"; \
		bash tests/compiler/elfobj-dump.sh; elfread_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_LINKINT)" = "1" ]; then \
		echo "==> Probe: --link-internal"; \
		bash tests/compiler/link-internal-smoke.sh; linkint_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST)" = "1" ]; then \
		echo "==> Selftest: host-built monacc -> monacc-self"; \
		bash tests/compiler/selftest.sh; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_EMITOBJ)" = "1" ]; then \
		echo "==> Selftest: --emit-obj"; \
		bash tests/compiler/selftest-emitobj.sh; emitobj_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(MULTI)" = "1" ]; then \
		echo "==> Matrix: build (monacc/gcc/clang)"; \
		sh tests/matrix/build-matrix.sh; matrix_rc=$$?; \
		echo ""; \
		echo "==> Matrix: smoke tests"; \
		sh tests/matrix/test-matrix.sh || matrix_rc=1; \
		echo ""; \
		echo "==> Matrix: size report (TSV)"; \
		mkdir -p build/matrix; \
		sh tests/matrix/size-report.sh > build/matrix/report.tsv || matrix_rc=1; \
		echo "Wrote build/matrix/report.tsv"; \
		sh tests/matrix/tsv-to-html.sh --out build/matrix/report.html || matrix_rc=1; \
		echo "Wrote build/matrix/report.html"; \
		echo ""; \
	fi; \
	if [ $$fail -eq 0 ] && [ $$tool_rc -eq 0 ] && [ $$elfread_rc -eq 0 ] && [ $$linkint_rc -eq 0 ] && [ $$emitobj_rc -eq 0 ] && [ $$matrix_rc -eq 0 ]; then \
		echo "All tests passed ($$ok examples, tools suite OK)"; \
	else \
		echo "Some tests failed (examples: $$fail failed, tools: exit $$tool_rc, elfread: exit $$elfread_rc, link-internal: exit $$linkint_rc, emit-obj: exit $$emitobj_rc, matrix: exit $$matrix_rc)"; \
		exit 1; \
	fi

# === Cleanup ===

clean:
	rm -rf bin build

# === Debug build ===

debug:
	$(MAKE) clean
	$(MAKE) DEBUG=1 LTO=0 all
