# monacc unified build
#
# Usage:
#   make        # Build compiler + all 90 tools
#   make test   # Build everything + run all tests
#   make clean  # Remove build artifacts

CC ?= cc
MONACC := bin/monacc

# Host shell executables used by Makefile-driven scripts.
# Keep these as the host defaults for now; as Step 8 closure matures, we can
# switch more callsites to HOST_SH=./bin/sh behind toggles.
HOST_SH ?= sh
HOST_BASH ?= bash

# Use the internal ELF object emitter by default (replaces external `as`).
# Set EMITOBJ=0 to force using the system assembler instead.
EMITOBJ ?= 1
ifeq ($(EMITOBJ),1)
MONACC_EMITOBJ_FLAG := --emit-obj
else
MONACC_EMITOBJ_FLAG :=
endif

# Use the internal linker by default when building via Makefile.
# Set LINKINT=0 to force using external `ld`.
LINKINT ?= 1
ifeq ($(LINKINT),1)
MONACC_LINK_FLAG := --link-internal
else
MONACC_LINK_FLAG :=
endif

# Build configuration
DEBUG ?= 0
LTO ?= 1
MULTI ?= 0

# Most distros default to PIE, which makes bin/monacc an ET_DYN + adds dynamic
# linker metadata. monacc doesn't need it (no external libs), so default to a
# smaller ET_EXEC binary. Set HOST_PIE=1 to keep the distro default.
HOST_PIE ?= 0

# Optional compiler probes.
# Note: the emit-obj probe is enabled by default and is treated as a normal test.
SELFTEST ?= 0
SELFTEST_EMITOBJ ?= 1
SELFTEST_ELFREAD ?= 1
SELFTEST_LINKINT ?= 1
SELFTEST_STAGE2 ?= 0
SELFTEST_STAGE2_INTERNAL ?= 0
SELFTEST_STAGE3 ?= 0
SELFTEST_BINSHELL ?= 0
SELFTEST_BINSHELL_BUILD ?= 0
SELFTEST_BINSHELL_TOOLS ?= 0
SELFTEST_BINSHELL_TOOLS_HARNESS ?= 0

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

ifeq ($(HOST_PIE),0)
CFLAGS += -fno-pie
LDFLAGS += -no-pie
endif


# Core sources
# Keep the compiler (bin/monacc) small by only linking the minimal core subset
# it actually uses. Tools still build against the full core.
CORE_MIN_SRC := \
	core/mc_str.c \
	core/mc_fmt.c \
	core/mc_snprint.c \
	core/mc_libc_compat.c \
	core/mc_start_env.c \
	core/mc_io.c \
	core/mc_regex.c

CORE_CRYPTO_SRC := \
	core/mc_sha256.c \
	core/mc_hmac.c \
	core/mc_hkdf.c \
	core/mc_aes.c \
	core/mc_gcm.c \
	core/mc_x25519.c

CORE_TLS_SRC := \
	core/mc_tls_record.c \
	core/mc_tls13.c \
	core/mc_tls13_transcript.c \
	core/mc_tls13_handshake.c

CORE_COMMON_SRC := $(CORE_MIN_SRC) $(CORE_CRYPTO_SRC) $(CORE_TLS_SRC)

# Hosted-only core sources (not built into MONACC tools)
CORE_HOSTED_SRC := \
	core/mc_start.c


CORE_TOOL_SRC := $(CORE_COMMON_SRC)
CORE_COMPILER_SRC := $(CORE_MIN_SRC) $(CORE_HOSTED_SRC)

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
	asm_syscall \
	float_arith float_div float_cmp float_neg float_lits

# Default goal: build everything
.DEFAULT_GOAL := all

.PHONY: all all-split tools-ld tools-internal test clean debug selfhost
.PHONY: matrix-tool matrix-mandelbrot
.PHONY: binsh-smoke
.PHONY: binsh-tools-smoke
.PHONY: binsh-tools-harness-smoke
.PHONY: closure-smoke
.PHONY: selfcontained-build-smoke

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
MONACC_SELF2 := bin/monacc-self2
MONACC_SELF3 := bin/monacc-self3

# Stage-2 knobs: keep defaults conservative while stage-2 correctness is being
# brought up. You can opt into the fully-internal pipeline once stable.
SELFHOST2_EMITOBJ ?= 1
SELFHOST2_LINKINT ?= 0

# Stage-3 knobs (default to stage-2 settings).
SELFHOST3_EMITOBJ ?= $(SELFHOST2_EMITOBJ)
SELFHOST3_LINKINT ?= $(SELFHOST2_LINKINT)
# monacc emits _start only for the first input file. Ensure that translation unit
# contains main(), otherwise the produced binary will be a trivial exit stub.
COMPILER_SELFHOST_SRC := \
	compiler/monacc_main.c \
	$(filter-out core/mc_start.c core/mc_vsnprintf.c compiler/monacc_main.c,$(COMPILER_SRC))

selfhost: $(MONACC_SELF)
	@echo ""
	@echo "Self-host build complete: $(MONACC_SELF)"

$(MONACC_SELF): $(COMPILER_SELFHOST_SRC) $(MONACC) | bin
	@echo "==> Building self-hosted compiler"
	@$(MONACC) $(MONACC_EMITOBJ_FLAG) $(MONACC_LINK_FLAG) -DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

# Stage-2 selfhost: rebuild the compiler using the self-built compiler.
# The assembler/linker internalization is controlled by SELFHOST2_EMITOBJ and
# SELFHOST2_LINKINT.
.PHONY: selfhost2
selfhost2: $(MONACC_SELF2)
	@echo ""
	@echo "Stage-2 self-host build complete: $(MONACC_SELF2)"

$(MONACC_SELF2): $(COMPILER_SELFHOST_SRC) $(MONACC_SELF) | bin
	@echo "==> Building stage-2 self-hosted compiler"
	@$(MONACC_SELF) $(if $(filter 1,$(SELFHOST2_EMITOBJ)),--emit-obj,) $(if $(filter 1,$(SELFHOST2_LINKINT)),--link-internal,) -DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

.PHONY: selfhost2-smoke
selfhost2-smoke: $(MONACC_SELF2)
	@echo "==> Stage-2 smoke: compile+run examples/hello.c"
	@mkdir -p build/selfhost2
	@./$(MONACC_SELF2) examples/hello.c -o build/selfhost2/hello-self2
	@set +e; ./build/selfhost2/hello-self2 >/dev/null; rc=$$?; set -e; \
		if [ $$rc -ne 42 ]; then echo "selfhost2-smoke: FAIL (rc=$$rc, expected 42)"; exit 1; fi
	@echo "selfhost2-smoke: OK"

# Step-8 bring-up: a minimal script that runs under ./bin/sh.
binsh-smoke: all
	@echo "==> bin/sh smoke: run minimal script"
	@./bin/sh tests/tools/binsh-minimal.sh
	@echo "binsh-smoke: OK"

# Step-8 bring-up: run a small real tools smoke under ./bin/sh.
binsh-tools-smoke: all
	@echo "==> bin/sh tools smoke: run small suite"
	@./bin/sh tests/tools/binsh-tools-smoke.sh
	@echo "binsh-tools-smoke: OK"

# Step-8 bring-up: run the canonical tools harness (smoke suite) under ./bin/sh.
binsh-tools-harness-smoke: all
	@echo "==> bin/sh tools harness: smoke suite"
	@SB_TEST_BIN="$$(pwd)/bin" SB_TEST_SHOW_SUITES=1 ./bin/sh tests/tools/run.sh smoke
	@echo "binsh-tools-harness-smoke: OK"

# Step-8 closure: run a self-contained smoke script under ./bin/sh.
closure-smoke: all
	@echo "==> closure smoke: compile+run under ./bin/sh"
	@./bin/sh scripts/selfcontained-smoke.sh
	@echo "closure-smoke: OK"

# Step-8 closure: rebuild compiler stages under ./bin/sh (heavier).
selfcontained-build-smoke: all
	@echo "==> selfcontained build: rebuild stages under ./bin/sh"
	@./bin/sh scripts/selfcontained-build.sh
	@echo "selfcontained-build-smoke: OK"

# Stage-3 selfhost: rebuild the compiler using the stage-2 compiler.
.PHONY: selfhost3
selfhost3: $(MONACC_SELF3)
	@echo ""
	@echo "Stage-3 self-host build complete: $(MONACC_SELF3)"

$(MONACC_SELF3): $(COMPILER_SELFHOST_SRC) $(MONACC_SELF2) | bin
	@echo "==> Building stage-3 self-hosted compiler"
	@$(MONACC_SELF2) $(if $(filter 1,$(SELFHOST3_EMITOBJ)),--emit-obj,) $(if $(filter 1,$(SELFHOST3_LINKINT)),--link-internal,) -DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

.PHONY: selfhost3-smoke
selfhost3-smoke: $(MONACC_SELF3)
	@echo "==> Stage-3 smoke: compile+run examples/hello.c"
	@mkdir -p build/selfhost3
	@./$(MONACC_SELF3) examples/hello.c -o build/selfhost3/hello-self3
	@set +e; ./build/selfhost3/hello-self3 >/dev/null; rc=$$?; set -e; \
		if [ $$rc -ne 42 ]; then echo "selfhost3-smoke: FAIL (rc=$$rc, expected 42)"; exit 1; fi
	@echo "selfhost3-smoke: OK"

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
	@$(MONACC) $(MONACC_EMITOBJ_FLAG) $(MONACC_LINK_FLAG) -I core $< $(CORE_TOOL_SRC) -o $@

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
	@if [ "$(LINKINT)" = "1" ]; then \
		echo "==> Building tools with monacc (internal linker)"; \
	else \
		echo "==> Building tools with monacc (external ld)"; \
	fi

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
	stage2_rc=0; \
	stage3_rc=0; \
	binsh_rc=0; \
	matrix_rc=0; \
	for ex in $(EXAMPLES); do \
		$(MONACC) $(MONACC_EMITOBJ_FLAG) $(MONACC_LINK_FLAG) examples/$$ex.c -o build/test/$$ex 2>/dev/null && \
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
	SB_TEST_BIN="$$(pwd)/bin" $(HOST_SH) tests/tools/run.sh; \
	tool_rc=$$?; \
	echo ""; \
	if [ "$(SELFTEST_ELFREAD)" = "1" ]; then \
		echo "==> Probe: ELF ET_REL reader"; \
		$(HOST_BASH) tests/compiler/elfobj-dump.sh; elfread_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_LINKINT)" = "1" ]; then \
		echo "==> Probe: --link-internal"; \
		$(HOST_BASH) tests/compiler/link-internal-smoke.sh; linkint_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST)" = "1" ]; then \
		echo "==> Selftest: host-built monacc -> monacc-self"; \
		$(HOST_BASH) tests/compiler/selftest.sh; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_EMITOBJ)" = "1" ]; then \
		echo "==> Selftest: --emit-obj"; \
		$(HOST_BASH) tests/compiler/selftest-emitobj.sh; emitobj_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_STAGE2)" = "1" ]; then \
		echo "==> Selftest: stage-2 (monacc-self -> monacc-self2)"; \
		SELFTEST_STAGE2_STRICT=1 SELFTEST_STAGE2_INTERNAL="$(SELFTEST_STAGE2_INTERNAL)" $(HOST_BASH) tests/compiler/selftest-stage2.sh; stage2_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_STAGE3)" = "1" ]; then \
		echo "==> Selftest: stage-3 (monacc-self2 -> monacc-self3)"; \
		SELFTEST_STAGE3_STRICT=1 $(HOST_BASH) tests/compiler/selftest-stage3.sh; stage3_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL)" = "1" ]; then \
		echo "==> Probe: run minimal script under ./bin/sh"; \
		./bin/sh tests/tools/binsh-minimal.sh; binsh_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL_TOOLS)" = "1" ]; then \
		echo "==> Probe: tools smoke under ./bin/sh"; \
		./bin/sh tests/tools/binsh-tools-smoke.sh || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL_TOOLS_HARNESS)" = "1" ]; then \
		echo "==> Probe: tools harness smoke under ./bin/sh"; \
		SB_TEST_BIN="$$(pwd)/bin" SB_TEST_SHOW_SUITES=1 ./bin/sh tests/tools/run.sh smoke || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL)" = "1" ]; then \
		echo "==> Probe: closure smoke under ./bin/sh"; \
		./bin/sh scripts/selfcontained-smoke.sh || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL_BUILD)" = "1" ]; then \
		echo "==> Probe: selfcontained build under ./bin/sh"; \
		./bin/sh scripts/selfcontained-build.sh || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(MULTI)" = "1" ]; then \
		echo "==> Matrix: build (monacc/gcc/clang)"; \
		$(HOST_SH) tests/matrix/build-matrix.sh; matrix_rc=$$?; \
		echo ""; \
		echo "==> Matrix: smoke tests"; \
		$(HOST_SH) tests/matrix/test-matrix.sh || matrix_rc=1; \
		echo ""; \
		echo "==> Matrix: size report (TSV)"; \
		mkdir -p build/matrix; \
		$(HOST_SH) tests/matrix/size-report.sh > build/matrix/report.tsv || matrix_rc=1; \
		echo "Wrote build/matrix/report.tsv"; \
		$(HOST_SH) tests/matrix/tsv-to-html.sh --out build/matrix/report.html || matrix_rc=1; \
		echo "Wrote build/matrix/report.html"; \
		echo ""; \
	fi; \
	if [ $$fail -eq 0 ] && [ $$tool_rc -eq 0 ] && [ $$elfread_rc -eq 0 ] && [ $$linkint_rc -eq 0 ] && [ $$emitobj_rc -eq 0 ] && [ $$stage2_rc -eq 0 ] && [ $$stage3_rc -eq 0 ] && [ $$binsh_rc -eq 0 ] && [ $$matrix_rc -eq 0 ]; then \
		echo "All tests passed ($$ok examples, tools suite OK)"; \
	else \
		echo "Some tests failed (examples: $$fail failed, tools: exit $$tool_rc, elfread: exit $$elfread_rc, link-internal: exit $$linkint_rc, emit-obj: exit $$emitobj_rc, stage2: exit $$stage2_rc, stage3: exit $$stage3_rc, bin/sh: exit $$binsh_rc, matrix: exit $$matrix_rc)"; \
		exit 1; \
	fi

# === Cleanup ===

clean:
	rm -rf bin build

# === Debug build ===

debug:
	$(MAKE) clean
	$(MAKE) DEBUG=1 LTO=0 all

# Build only one tool across multiple toolchains (monacc + gcc/clang), without
# compiling all other tools.
#
# Examples:
#   make matrix-tool TOOL=mandelbrot
#   make matrix-tool TOOL=mandelbrot TCS="monacc gcc-15 clang-20"
#
TOOL ?= mandelbrot
TCS ?=

matrix-tool: $(MONACC)
	@echo "==> Matrix: build tool=$(TOOL)"
	@mkdir -p build/matrix
	@MATRIX_TOOLS="$(TOOL)" sh tests/matrix/build-matrix.sh $(TCS)

matrix-mandelbrot:
	@$(MAKE) matrix-tool TOOL=mandelbrot TCS="$(TCS)"
