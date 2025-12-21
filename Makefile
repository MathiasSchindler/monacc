# monacc unified build
#
# Usage:
#   make        # Build compiler + all tools
#   make test   # Build everything + run all tests
#   make clean  # Remove build artifacts

CC ?= cc
MONACC := bin/monacc

# Host shell executables used by Makefile-driven scripts.
# Keep these as the host defaults for now; as Step 8 closure matures, we can
# switch more callsites to HOST_SH=./bin/sh behind toggles.
HOST_SH ?= sh
HOST_BASH ?= bash

# monacc defaults to internal object emission + internal linking.
# These knobs exist to force external tools for bring-up/debugging.
#
# - EMITOBJ=0 forces external assembler (equivalent to passing --as as)
# - LINKINT=0 forces external linker (equivalent to passing --ld ld)
EMITOBJ ?= 1
ifeq ($(EMITOBJ),1)
MONACC_AS_FLAG :=
else
MONACC_AS_FLAG := --as as
endif

LINKINT ?= 1
ifeq ($(LINKINT),1)
MONACC_LD_FLAG :=
else
MONACC_LD_FLAG := --ld ld
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
SELFTEST_MATHF ?= 1
SELFTEST_STAGE2 ?= 0
SELFTEST_STAGE2_INTERNAL ?= 0
SELFTEST_STAGE3 ?= 0
SELFTEST_BINSHELL ?= 0
SELFTEST_BINSHELL_BUILD ?= 0
SELFTEST_BINSHELL_TOOLS ?= 0
SELFTEST_BINSHELL_TOOLS_HARNESS ?= 0

# Compiler regression tests for known bug fixes (see docs/monaccbugs.md).
# Runs as part of `make test` by default; set SELFTEST_MONACCBUGS=0 to skip.
SELFTEST_MONACCBUGS ?= 1

# Repo guardrails (fast grep-based checks).
SELFTEST_REPO_GUARDS ?= 1

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
	core/mc_tls13_handshake.c \
	core/mc_tls13_client.c

CORE_MATH_SRC := \
	core/mc_mathf.c

CORE_COMMON_SRC := $(CORE_MIN_SRC) $(CORE_CRYPTO_SRC) $(CORE_TLS_SRC) $(CORE_MATH_SRC)

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

# Tools with extra translation units (submodules)
MASTO_SRCS := tools/masto.c $(wildcard tools/masto/*.c)

# Examples to test (must return exit code 42)
EXAMPLES := hello loop pp ptr charlit strlit sizeof struct proto typedef \
	typedef_multi enum enum_constexpr struct_array fnptr_member ternary \
	cast cast_void logical bitwise_or_xor hex_macro call7 struct_copy \
	array_constexpr prefix_incdec compound_literal postinc_member_array sret_cond \
	unsigned_divmod_pow2 const_index sizeof_array packed_struct compound_literal_assign_global extern_incomplete_array static_local_array static_local_init \
	global_array_store \
	addr_deref_syscall \
	asm_syscall \
	float_arith float_div float_cmp float_neg float_lits \
	float_call_ret float_call_mixed float_call_many \
	float_cast_callargs

# Default goal: build everything
.DEFAULT_GOAL := all

.PHONY: all all-split tools-ld tools-internal test clean debug selfhost
.PHONY: matrix-tool matrix-mandelbrot
.PHONY: darwin-tools
.PHONY: darwin-smoke
.PHONY: darwin-monacc
.PHONY: darwin-monacc-smoke
.PHONY: darwin-native-smoke
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

# Which tool should be installed as /init inside the initramfs.
# For sysbox on Linux, the default `init` mounts /dev,/proc,/sys and spawns /bin/sh.
# For the experimental kernel bring-up, `kinit` is often more appropriate.
INITRAMFS_INIT ?= init

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
# brought up.
#
# Notes:
# - SELFHOST*_EMITOBJ=0 forces external assembler via "--as as".
# - SELFHOST*_LINKINT=0 forces external linker via "--ld ld".
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
	@$(MONACC) $(MONACC_AS_FLAG) $(MONACC_LD_FLAG) -DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

# Stage-2 selfhost: rebuild the compiler using the self-built compiler.
# The assembler/linker internalization is controlled by SELFHOST2_EMITOBJ and
# SELFHOST2_LINKINT.
.PHONY: selfhost2
selfhost2: $(MONACC_SELF2)
	@echo ""
	@echo "Stage-2 self-host build complete: $(MONACC_SELF2)"

$(MONACC_SELF2): $(COMPILER_SELFHOST_SRC) $(MONACC_SELF) | bin
	@echo "==> Building stage-2 self-hosted compiler"
	@$(MONACC_SELF) \
		$(if $(filter 0,$(SELFHOST2_EMITOBJ)),--as as,) \
		$(if $(filter 0,$(SELFHOST2_LINKINT)),--ld ld,) \
		-DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

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
	@./bin/sh tests/closure/selfcontained-smoke.sh
	@echo "closure-smoke: OK"

# Step-8 closure: rebuild compiler stages under ./bin/sh (heavier).
selfcontained-build-smoke: all
	@echo "==> selfcontained build: rebuild stages under ./bin/sh"
	@./bin/sh tests/closure/selfcontained-build.sh
	@echo "selfcontained-build-smoke: OK"

# Stage-3 selfhost: rebuild the compiler using the stage-2 compiler.
.PHONY: selfhost3
selfhost3: $(MONACC_SELF3)
	@echo ""
	@echo "Stage-3 self-host build complete: $(MONACC_SELF3)"

$(MONACC_SELF3): $(COMPILER_SELFHOST_SRC) $(MONACC_SELF2) | bin
	@echo "==> Building stage-3 self-hosted compiler"
	@$(MONACC_SELF2) \
		$(if $(filter 0,$(SELFHOST3_EMITOBJ)),--as as,) \
		$(if $(filter 0,$(SELFHOST3_LINKINT)),--ld ld,) \
		-DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

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
	@cp -a $(INITRAMFS_ROOT)/bin/$(INITRAMFS_INIT) $(INITRAMFS_ROOT)/init

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

# masto is split into tools/masto.c + tools/masto/*.c
# Ensure the first file is tools/masto.c so monacc emits _start correctly.
bin/masto: $(MASTO_SRCS) $(CORE_TOOL_SRC) $(MONACC) | bin
	@echo "  masto"
	@$(MONACC) $(MONACC_AS_FLAG) $(MONACC_LD_FLAG) -I core tools/masto.c $(filter-out tools/masto.c,$(MASTO_SRCS)) $(CORE_TOOL_SRC) -o $@

bin/ld/masto: $(MASTO_SRCS) $(CORE_TOOL_SRC) $(MONACC) | bin/ld
	@echo "  ld/masto"
	@$(MONACC) $(MONACC_AS_FLAG) --ld ld -I core tools/masto.c $(filter-out tools/masto.c,$(MASTO_SRCS)) $(CORE_TOOL_SRC) -o $@

bin/internal/masto: $(MASTO_SRCS) $(CORE_TOOL_SRC) $(MONACC) | bin/internal
	@echo "  internal/masto"
	@$(MONACC) $(MONACC_AS_FLAG) --link-internal -I core tools/masto.c $(filter-out tools/masto.c,$(MASTO_SRCS)) $(CORE_TOOL_SRC) -o $@

bin/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin
	@echo "  $*"
	@$(MONACC) $(MONACC_AS_FLAG) $(MONACC_LD_FLAG) -I core $< $(CORE_TOOL_SRC) -o $@

# External-ld linked toolset (kept separate for comparison)
bin/ld/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin/ld
	@echo "  ld/$*"
	@$(MONACC) $(MONACC_AS_FLAG) --ld ld -I core $< $(CORE_TOOL_SRC) -o $@

# Internal-linker toolset
bin/internal/%: tools/%.c $(CORE_TOOL_SRC) $(MONACC) | bin/internal
	@echo "  internal/$*"
	@$(MONACC) $(MONACC_AS_FLAG) --link-internal -I core $< $(CORE_TOOL_SRC) -o $@

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
	mathf_rc=0; \
	stage2_rc=0; \
	stage3_rc=0; \
	monaccbugs_rc=0; \
	binsh_rc=0; \
	matrix_rc=0; repo_guard_rc=0; \
	for ex in $(EXAMPLES); do \
		$(MONACC) $(MONACC_AS_FLAG) $(MONACC_LD_FLAG) examples/$$ex.c -o build/test/$$ex 2>/dev/null && \
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
	if [ "$(SELFTEST_MATHF)" = "1" ]; then \
		echo "==> Selftest: mc_mathf + tensor helpers"; \
		$(HOST_BASH) tests/compiler/selftest-mathf.sh; mathf_rc=$$?; \
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
	if [ "$(SELFTEST_MONACCBUGS)" = "1" ]; then \
		echo "==> Regression: compiler bugfix suite (docs/monaccbugs.md)"; \
		$(HOST_BASH) tests/compiler/monaccbugs.sh; monaccbugs_rc=$$?; \
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
		./bin/sh tests/closure/selfcontained-smoke.sh || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL_BUILD)" = "1" ]; then \
		echo "==> Probe: selfcontained build under ./bin/sh"; \
		./bin/sh tests/closure/selfcontained-build.sh || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_REPO_GUARDS)" = "1" ]; then \
		echo "==> Probe: repo guardrails"; \
		$(HOST_SH) tests/repo/no-kernel-binutils-creep.sh .; repo_guard_rc=$$?; \
		$(HOST_SH) tests/repo/function-overlap.sh . || repo_guard_rc=1; \
		echo ""; \
	fi; \
	if [ "$(MULTI)" = "1" ]; then \
		echo "==> Matrix: build (override with MATRIX_TCS=\"monacc gcc-15 clang-21\")"; \
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
		echo "==> Matrix: matrixstat report (TSV)"; \
		$(HOST_SH) tests/matrix/matrixstat-report.sh > /dev/null || matrix_rc=1; \
		echo "Wrote build/matrix/matrixstat.tsv"; \
		echo ""; \
	fi; \
	if [ $$fail -eq 0 ] && [ $$tool_rc -eq 0 ] && [ $$elfread_rc -eq 0 ] && [ $$linkint_rc -eq 0 ] && [ $$emitobj_rc -eq 0 ] && [ $$mathf_rc -eq 0 ] && [ $$stage2_rc -eq 0 ] && [ $$stage3_rc -eq 0 ] && [ $$monaccbugs_rc -eq 0 ] && [ $$binsh_rc -eq 0 ] && [ $$repo_guard_rc -eq 0 ] && [ $$matrix_rc -eq 0 ]; then \
		echo "All tests passed ($$ok examples, tools suite OK)"; \
	else \
		echo "Some tests failed (examples: $$fail failed, tools: exit $$tool_rc, elfread: exit $$elfread_rc, link-internal: exit $$linkint_rc, emit-obj: exit $$emitobj_rc, mathf: exit $$mathf_rc, stage2: exit $$stage2_rc, stage3: exit $$stage3_rc, monaccbugs: exit $$monaccbugs_rc, bin/sh: exit $$binsh_rc, repo-guards: exit $$repo_guard_rc, matrix: exit $$matrix_rc)"; \
		exit 1; \
	fi

# === Cleanup ===

clean:
	rm -rf bin build $(HOST_BIN)

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
#   MATRIX_TCS="monacc gcc-15 clang-21" make matrix-tool TOOL=mandelbrot
#
TOOL ?= mandelbrot
TCS ?=

matrix-tool: $(MONACC)
	@echo "==> Matrix: build tool=$(TOOL)"
	@mkdir -p build/matrix
	@MATRIX_TOOLS="$(TOOL)" sh tests/matrix/build-matrix.sh $(TCS)

matrix-mandelbrot:
	@$(MAKE) matrix-tool TOOL=mandelbrot TCS="$(TCS)"

# === Hosted macOS build (clang + libc) ===

# Output directory for hosted tool builds (separate from syscall-only bin/).
HOST_BIN ?= bin-host
HOST_TOOLS_CC ?= clang
HOST_TOOLS_CFLAGS ?= -Os -DNDEBUG -Wall -Wextra -Wpedantic \
	-ffunction-sections -fdata-sections \
	-fno-unwind-tables -fno-asynchronous-unwind-tables \
	-Wno-macro-redefined \
	-Wno-tautological-constant-out-of-range-compare
HOST_TOOLS_CFLAGS += \
	-Wno-unused-function \
	-Wno-unused-parameter \
	-Wno-unused-but-set-variable \
	-Wno-sizeof-array-argument \
	-Wno-for-loop-analysis \
	-Wno-c23-extensions

HOST_TOOLS_LDFLAGS ?= -Wl,-dead_strip

# Core sources needed when building tools with a host toolchain.
# Note: exclude Linux-only startup (`core/mc_start.c`).
HOST_CORE_SRC := $(filter-out core/mc_libc_compat.c,$(CORE_COMMON_SRC))

# Header dependencies for hosted tools.
# The hosted build compiles tools in a single step (no .o files), so we must
# explicitly list headers as prerequisites to ensure changes in core/*.h trigger
# a rebuild.
HOST_CORE_HDR := $(wildcard core/*.h)

# Hosted compiler header deps.
HOST_COMPILER_HDR := $(wildcard compiler/*.h)

$(HOST_BIN):
	mkdir -p $(HOST_BIN)

HOST_TOOL_BINS := $(addprefix $(HOST_BIN)/,$(TOOL_NAMES))

# Hosted monacc build (compiler itself). This builds a libc-linked binary that
# can run on macOS, but still targets Linux/x86_64 in its output.
HOST_MONACC_CC ?= $(HOST_TOOLS_CC)
HOST_MONACC_CFLAGS ?= $(HOST_TOOLS_CFLAGS)
HOST_MONACC_LDFLAGS ?= $(HOST_TOOLS_LDFLAGS)

HOST_MONACC_SRC := $(filter-out core/mc_libc_compat.c core/mc_start.c,$(COMPILER_SRC))

$(HOST_BIN)/monacc: $(HOST_MONACC_SRC) $(HOST_CORE_HDR) $(HOST_COMPILER_HDR) | $(HOST_BIN)
	@echo "  monacc"
	@$(HOST_MONACC_CC) $(HOST_MONACC_CFLAGS) $(HOST_MONACC_LDFLAGS) -I core -I compiler $(HOST_MONACC_SRC) -o $@

# Default rule for single-file tools.
$(HOST_BIN)/%: tools/%.c $(HOST_CORE_SRC) $(HOST_CORE_HDR) | $(HOST_BIN)
	@echo "  $*"
	@$(HOST_TOOLS_CC) $(HOST_TOOLS_CFLAGS) $(HOST_TOOLS_LDFLAGS) -I core $< $(HOST_CORE_SRC) -o $@

# Tools with extra translation units.
$(HOST_BIN)/masto: $(MASTO_SRCS) $(HOST_CORE_SRC) $(HOST_CORE_HDR) | $(HOST_BIN)
	@echo "  masto"
	@$(HOST_TOOLS_CC) $(HOST_TOOLS_CFLAGS) $(HOST_TOOLS_LDFLAGS) -I core $(MASTO_SRCS) $(HOST_CORE_SRC) -o $@

# Compatibility aliases expected by the repo.
$(HOST_BIN)/realpath: $(HOST_BIN)/readlink | $(HOST_BIN)
	@cp -f $< $@

$(HOST_BIN)/[: $(HOST_BIN)/test | $(HOST_BIN)
	@cp -f $< $@

darwin-tools: $(HOST_TOOL_BINS) $(HOST_BIN)/realpath $(HOST_BIN)/[
	@echo "Hosted build complete: $(HOST_BIN)/*"

darwin-monacc: $(HOST_BIN)/monacc
	@echo "Hosted compiler build complete: $(HOST_BIN)/monacc"

darwin-smoke: darwin-tools
	@echo "==> Smoke: macOS hosted tools"
	@test -x $(HOST_BIN)/true && $(HOST_BIN)/true
	@test -x $(HOST_BIN)/pwd && $(HOST_BIN)/pwd >/dev/null
	@if test -x $(HOST_BIN)/echo && test -x $(HOST_BIN)/cat; then \
		$(HOST_BIN)/echo "smoke" | $(HOST_BIN)/cat >/dev/null; \
	fi
	@echo "Smoke complete"

darwin-monacc-smoke: darwin-monacc
	@echo "==> Smoke: macOS hosted compiler"
	@test -x $(HOST_BIN)/monacc
	@rm -f $(HOST_BIN)/hello.elf
	@$(HOST_BIN)/monacc examples/hello.c -o $(HOST_BIN)/hello.elf >/dev/null
	@test -s $(HOST_BIN)/hello.elf
	@echo "Compiler smoke complete"

darwin-native-smoke: darwin-monacc
	@echo "==> Smoke: macOS native aarch64-darwin target"
	@rm -f $(HOST_BIN)/ret42
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42.c -o $(HOST_BIN)/ret42 >/dev/null
	@test -x $(HOST_BIN)/ret42
	@rc=0; $(HOST_BIN)/ret42 || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_local
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_local.c -o $(HOST_BIN)/ret42_local >/dev/null
	@test -x $(HOST_BIN)/ret42_local
	@rc=0; $(HOST_BIN)/ret42_local || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_if
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_if.c -o $(HOST_BIN)/ret42_if >/dev/null
	@test -x $(HOST_BIN)/ret42_if
	@rc=0; $(HOST_BIN)/ret42_if || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_while
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_while.c -o $(HOST_BIN)/ret42_while >/dev/null
	@test -x $(HOST_BIN)/ret42_while
	@rc=0; $(HOST_BIN)/ret42_while || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_while_dec
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_while_dec.c -o $(HOST_BIN)/ret42_while_dec >/dev/null
	@test -x $(HOST_BIN)/ret42_while_dec
	@rc=0; $(HOST_BIN)/ret42_while_dec || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_call
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_call.c -o $(HOST_BIN)/ret42_call >/dev/null
	@test -x $(HOST_BIN)/ret42_call
	@rc=0; $(HOST_BIN)/ret42_call || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_break_continue
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_break_continue.c -o $(HOST_BIN)/ret42_break_continue >/dev/null
	@test -x $(HOST_BIN)/ret42_break_continue
	@rc=0; $(HOST_BIN)/ret42_break_continue || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_call_args
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_call_args.c -o $(HOST_BIN)/ret42_call_args >/dev/null
	@test -x $(HOST_BIN)/ret42_call_args
	@rc=0; $(HOST_BIN)/ret42_call_args || rc=$$?; test $$rc -eq 42
	@echo "Native smoke complete"

darwin-net-smoke: darwin-tools
	@echo "==> Smoke: macOS hosted networking"
	@test -x $(HOST_BIN)/tcp6
	@$(HOST_BIN)/tcp6 -W 5000 2001:4860:4860::8888 53
	@if test -x $(HOST_BIN)/wtf; then \
		$(HOST_BIN)/wtf -W 5000 Google >/dev/null; \
	fi
	@echo "Net smoke complete"

