# monacc unified build
#
# Main Targets:
#   make              Build compiler + all tools
#   make test         Build everything + run all tests
#   MULTI=1 make test Run full platform/tool matrix build & test
#   make clean        Remove all build artifacts
#
# Optional initramfs targets for kernel bring-up:
#   make initramfs    Build compressed initramfs for experimental kernel
#
# Build Configuration (set via environment or make arguments):
#   DEBUG=1           Build with debug symbols, no optimization
#   LTO=1             Enable link-time optimization (default: 1)
#   EMITOBJ=0         Force external assembler (--as as)
#   LINKINT=0         Force external linker (--ld ld)
#   HOST_PIE=1        Enable position-independent executable
#
# Test Configuration:
#   All test groups are enabled by default. To disable specific groups:
#   SELFTEST_PHASE1=0        Disable Phase 1 compiler smoke tests
#   SELFTEST_EMITOBJ=0       Disable object emission tests
#   SELFTEST_ELFREAD=0       Disable ELF reader tests
#   SELFTEST_LINKINT=0       Disable internal linker tests
#   SELFTEST_MATHF=0         Disable math function tests
#   SELFTEST_STAGE2=0        Disable stage-2 self-hosting tests
#   SELFTEST_STAGE3=0        Disable stage-3 self-hosting tests
#   SELFTEST_MONACCBUGS=0    Disable regression tests
#   SELFTEST_BINSHELL=0      Disable bin/sh execution tests
#   SELFTEST_REPO_GUARDS=0   Disable repository guardrail checks

CC ?= cc
MONACC := bin/monacc

UNAME_S := $(shell uname -s 2>/dev/null || echo unknown)

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

# macOS UX: by default, run the hosted+aarch64-darwin matrix when invoking the
# top-level entrypoints (`make` / `make test`).
ifeq ($(UNAME_S),Darwin)
DARWIN_NATIVE_MATRIX ?= 1
.DEFAULT_GOAL := darwin-native-smoke
endif

# Most distros default to PIE, which makes bin/monacc an ET_DYN + adds dynamic
# linker metadata. monacc doesn't need it (no external libs), so default to a
# smaller ET_EXEC binary. Set HOST_PIE=1 to keep the distro default.
HOST_PIE ?= 0

# All tests are enabled by default as part of `make test`.
# Advanced users can disable specific test groups by setting these to 0.
# - SELFTEST_PHASE1: Phase 1 compiler smoke tests (fundamental invariants)
# - SELFTEST_EMITOBJ: Object emission tests
# - SELFTEST_ELFREAD: ELF reader tests
# - SELFTEST_LINKINT: Internal linker tests
# - SELFTEST_MATHF: Math function tests
# - SELFTEST_STAGE2: Stage-2 self-hosting tests
# - SELFTEST_STAGE3: Stage-3 self-hosting tests
# - SELFTEST_MONACCBUGS: Regression tests (docs/monaccbugs.md)
# - SELFTEST_BINSHELL: bin/sh execution tests
# - SELFTEST_REPO_GUARDS: Repository guardrail checks
SELFTEST_PHASE1 ?= 1
SELFTEST_EMITOBJ ?= 1
SELFTEST_ELFREAD ?= 1
SELFTEST_LINKINT ?= 1
SELFTEST_MATHF ?= 1
SELFTEST_STAGE2 ?= 1
SELFTEST_STAGE3 ?= 1
SELFTEST_MONACCBUGS ?= 1
SELFTEST_BINSHELL ?= 1
SELFTEST_REPO_GUARDS ?= 1

CFLAGS_BASE := -Wall -Wextra -Wpedantic -fno-stack-protector
ifeq ($(DEBUG),1)
CFLAGS := -O0 -g $(CFLAGS_BASE)
LDFLAGS :=
else
CFLAGS := -Os -DNDEBUG $(CFLAGS_BASE) -ffunction-sections -fdata-sections \
	-fno-unwind-tables -fno-asynchronous-unwind-tables
ifeq ($(UNAME_S),Darwin)
# macOS ld does not support GNU ld's --gc-sections; use dead_strip instead.
LDFLAGS := -Wl,-dead_strip
else
LDFLAGS := -s -Wl,--gc-sections
endif
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

# Default goal: build everything (except on macOS where we default to native smoke)
ifneq ($(UNAME_S),Darwin)
.DEFAULT_GOAL := all
endif

.PHONY: all test clean

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

# === Self-hosting support (used by test target) ===

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

$(MONACC_SELF): $(COMPILER_SELFHOST_SRC) $(MONACC) | bin
	@echo "==> Building self-hosted compiler"
	@$(MONACC) $(MONACC_AS_FLAG) $(MONACC_LD_FLAG) -DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

# Internal targets for test scripts (not user-facing)
.PHONY: selfhost selfhost2 selfhost3
selfhost: $(MONACC_SELF)
selfhost2: $(MONACC_SELF2)
selfhost3: $(MONACC_SELF3)

$(MONACC_SELF2): $(COMPILER_SELFHOST_SRC) $(MONACC_SELF) | bin
	@echo "==> Building stage-2 self-hosted compiler"
	@$(MONACC_SELF) \
		$(if $(filter 0,$(SELFHOST2_EMITOBJ)),--as as,) \
		$(if $(filter 0,$(SELFHOST2_LINKINT)),--ld ld,) \
		-DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

$(MONACC_SELF3): $(COMPILER_SELFHOST_SRC) $(MONACC_SELF2) | bin
	@echo "==> Building stage-3 self-hosted compiler"
	@$(MONACC_SELF2) \
		$(if $(filter 0,$(SELFHOST3_EMITOBJ)),--as as,) \
		$(if $(filter 0,$(SELFHOST3_LINKINT)),--ld ld,) \
		-DSELFHOST -I core -I compiler $(COMPILER_SELFHOST_SRC) -o $@

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

ifeq ($(UNAME_S),Darwin)

# On macOS, the syscall-only Linux userland binaries are not runnable.
# Use the hosted toolchain + native aarch64-darwin target smoke by default.
test:
	@echo ""
	@echo "==> Testing (macOS)"
	@$(MAKE) darwin-native-smoke
	@if [ "$(MULTI)" = "1" ]; then \
		echo ""; \
		echo "==> MULTI=1: also building hosted tools with $(HOST_TOOLS_CC)"; \
		$(MAKE) darwin-tools; \
		echo ""; \
		echo "Binaries:"; \
		echo "  - hosted (clang/cc): $(HOST_BIN)/*"; \
		echo "  - monacc native: $(HOST_BIN)/matrix-bin/*-mc"; \
	fi
	@echo "All tests passed (macOS native smoke OK)"

else

test: all
	@echo ""
	@echo "==> Testing examples"
	@mkdir -p build/test
	@ok=0; fail=0; \
	phase1_rc=0; \
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
	if [ "$(SELFTEST_PHASE1)" = "1" ]; then \
		echo "==> Testing: Phase 1 smoke tests"; \
		$(HOST_BASH) tests/compiler/phase1-smoke.sh; phase1_rc=$$?; \
		echo ""; \
	fi; \
	echo "==> Testing tools"; \
	SB_TEST_BIN="$$(pwd)/bin" $(HOST_SH) tests/tools/run.sh; \
	tool_rc=$$?; \
	echo ""; \
	if [ "$(SELFTEST_ELFREAD)" = "1" ]; then \
		echo "==> Testing: ELF ET_REL reader"; \
		$(HOST_BASH) tests/compiler/elfobj-dump.sh; elfread_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_LINKINT)" = "1" ]; then \
		echo "==> Testing: --link-internal"; \
		$(HOST_BASH) tests/compiler/link-internal-smoke.sh; linkint_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_MATHF)" = "1" ]; then \
		echo "==> Testing: mc_mathf + tensor helpers"; \
		$(HOST_BASH) tests/compiler/selftest-mathf.sh; mathf_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_EMITOBJ)" = "1" ]; then \
		echo "==> Testing: --emit-obj"; \
		$(HOST_BASH) tests/compiler/selftest-emitobj.sh; emitobj_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_STAGE2)" = "1" ] || [ "$(SELFTEST_STAGE3)" = "1" ]; then \
		if [ ! -f $(MONACC_SELF) ]; then \
			echo "==> Building self-hosted compiler (stage-1)"; \
			$(MAKE) $(MONACC_SELF); \
		fi; \
	fi; \
	if [ "$(SELFTEST_STAGE2)" = "1" ]; then \
		echo "==> Testing: stage-2 (monacc-self -> monacc-self2)"; \
		$(HOST_BASH) tests/compiler/selftest-stage2.sh; stage2_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_STAGE3)" = "1" ]; then \
		echo "==> Testing: stage-3 (monacc-self2 -> monacc-self3)"; \
		$(HOST_BASH) tests/compiler/selftest-stage3.sh; stage3_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_MONACCBUGS)" = "1" ]; then \
		echo "==> Regression: compiler bugfix suite (docs/monaccbugs.md)"; \
		$(HOST_BASH) tests/compiler/monaccbugs.sh; monaccbugs_rc=$$?; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_BINSHELL)" = "1" ]; then \
		echo "==> Testing: bin/sh execution"; \
		./bin/sh tests/tools/binsh-minimal.sh || binsh_rc=1; \
		./bin/sh tests/tools/binsh-tools-smoke.sh || binsh_rc=1; \
		SB_TEST_BIN="$$(pwd)/bin" SB_TEST_SHOW_SUITES=1 ./bin/sh tests/tools/run.sh smoke || binsh_rc=1; \
		./bin/sh tests/closure/selfcontained-smoke.sh || binsh_rc=1; \
		./bin/sh tests/closure/selfcontained-build.sh || binsh_rc=1; \
		echo ""; \
	fi; \
	if [ "$(SELFTEST_REPO_GUARDS)" = "1" ]; then \
		echo "==> Testing: repository guardrails"; \
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
	if [ $$fail -eq 0 ] && [ $$phase1_rc -eq 0 ] && [ $$tool_rc -eq 0 ] && [ $$elfread_rc -eq 0 ] && [ $$linkint_rc -eq 0 ] && [ $$emitobj_rc -eq 0 ] && [ $$mathf_rc -eq 0 ] && [ $$stage2_rc -eq 0 ] && [ $$stage3_rc -eq 0 ] && [ $$monaccbugs_rc -eq 0 ] && [ $$binsh_rc -eq 0 ] && [ $$repo_guard_rc -eq 0 ] && [ $$matrix_rc -eq 0 ]; then \
		echo "All tests passed ($$ok examples, tools suite OK)"; \
	else \
		echo "Some tests failed (examples: $$fail failed, phase1: exit $$phase1_rc, tools: exit $$tool_rc, elfread: exit $$elfread_rc, link-internal: exit $$linkint_rc, emit-obj: exit $$emitobj_rc, mathf: exit $$mathf_rc, stage2: exit $$stage2_rc, stage3: exit $$stage3_rc, monaccbugs: exit $$monaccbugs_rc, bin/sh: exit $$binsh_rc, repo-guards: exit $$repo_guard_rc, matrix: exit $$matrix_rc)"; \
		exit 1; \
	fi

endif

# === Cleanup ===

clean:
	rm -rf bin build $(HOST_BIN)

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
	@rm -f $(HOST_BIN)/ret42_preinc
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_preinc.c -o $(HOST_BIN)/ret42_preinc >/dev/null
	@test -x $(HOST_BIN)/ret42_preinc
	@rc=0; $(HOST_BIN)/ret42_preinc || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_postinc
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_postinc.c -o $(HOST_BIN)/ret42_postinc >/dev/null
	@test -x $(HOST_BIN)/ret42_postinc
	@rc=0; $(HOST_BIN)/ret42_postinc || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_predec
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_predec.c -o $(HOST_BIN)/ret42_predec >/dev/null
	@test -x $(HOST_BIN)/ret42_predec
	@rc=0; $(HOST_BIN)/ret42_predec || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_postdec
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_postdec.c -o $(HOST_BIN)/ret42_postdec >/dev/null
	@test -x $(HOST_BIN)/ret42_postdec
	@rc=0; $(HOST_BIN)/ret42_postdec || rc=$$?; test $$rc -eq 42
	@echo "  ... ret42 inc/dec OK"
	@rm -f $(HOST_BIN)/ret42_inc_stmt
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_inc_stmt.c -o $(HOST_BIN)/ret42_inc_stmt >/dev/null
	@test -x $(HOST_BIN)/ret42_inc_stmt
	@rc=0; $(HOST_BIN)/ret42_inc_stmt || rc=$$?; test $$rc -eq 42
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
	@echo "  ... ret42 control flow OK"
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
	@rm -f $(HOST_BIN)/ret42_call_args9
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_call_args9.c -o $(HOST_BIN)/ret42_call_args9 >/dev/null
	@test -x $(HOST_BIN)/ret42_call_args9
	@rc=0; $(HOST_BIN)/ret42_call_args9 || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_puts
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_puts.c -o $(HOST_BIN)/ret42_puts >/dev/null
	@test -x $(HOST_BIN)/ret42_puts
	@rc=0; $(HOST_BIN)/ret42_puts >/dev/null || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_global
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_global.c -o $(HOST_BIN)/ret42_global >/dev/null
	@test -x $(HOST_BIN)/ret42_global
	@rc=0; $(HOST_BIN)/ret42_global || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_ptr_local
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_ptr_local.c -o $(HOST_BIN)/ret42_ptr_local >/dev/null
	@test -x $(HOST_BIN)/ret42_ptr_local
	@rc=0; $(HOST_BIN)/ret42_ptr_local || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_ptr_store
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_ptr_store.c -o $(HOST_BIN)/ret42_ptr_store >/dev/null
	@test -x $(HOST_BIN)/ret42_ptr_store
	@rc=0; $(HOST_BIN)/ret42_ptr_store || rc=$$?; test $$rc -eq 42
	@echo "  ... ret42 globals/ptrs OK"
	@rm -f $(HOST_BIN)/ret42_global_store
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_global_store.c -o $(HOST_BIN)/ret42_global_store >/dev/null
	@test -x $(HOST_BIN)/ret42_global_store
	@rc=0; $(HOST_BIN)/ret42_global_store || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_cmp_expr
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_cmp_expr.c -o $(HOST_BIN)/ret42_cmp_expr >/dev/null
	@test -x $(HOST_BIN)/ret42_cmp_expr
	@rc=0; $(HOST_BIN)/ret42_cmp_expr || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_cmp_eqne
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_cmp_eqne.c -o $(HOST_BIN)/ret42_cmp_eqne >/dev/null
	@test -x $(HOST_BIN)/ret42_cmp_eqne
	@rc=0; $(HOST_BIN)/ret42_cmp_eqne || rc=$$?; test $$rc -eq 42
	@echo "==> Smoke: macOS native tools (aarch64-darwin)"
	@rm -f \
		$(HOST_BIN)/true-mc \
		$(HOST_BIN)/false-mc \
		$(HOST_BIN)/echo-mc \
		$(HOST_BIN)/cat-mc \
		$(HOST_BIN)/env-mc \
		$(HOST_BIN)/which-mc \
		$(HOST_BIN)/nproc-mc \
		$(HOST_BIN)/readlink-mc \
		$(HOST_BIN)/stat-mc \
		$(HOST_BIN)/xargs-mc \
		$(HOST_BIN)/cmp-mc \
		$(HOST_BIN)/diff-mc \
		$(HOST_BIN)/printf-mc \
		$(HOST_BIN)/date-mc \
		$(HOST_BIN)/expr-mc \
		$(HOST_BIN)/grep-mc \
		$(HOST_BIN)/sed-mc \
		$(HOST_BIN)/basename-mc \
		$(HOST_BIN)/dirname-mc \
		$(HOST_BIN)/whoami-mc \
		$(HOST_BIN)/pwd-mc \
		$(HOST_BIN)/hostname-mc \
		$(HOST_BIN)/id-mc \
		$(HOST_BIN)/uname-mc \
		$(HOST_BIN)/head-mc \
		$(HOST_BIN)/tail-mc \
		$(HOST_BIN)/wc-mc \
		$(HOST_BIN)/tr-mc \
		$(HOST_BIN)/cut-mc \
		$(HOST_BIN)/uniq-mc \
		$(HOST_BIN)/paste-mc \
		$(HOST_BIN)/nl-mc \
		$(HOST_BIN)/sort-mc \
		$(HOST_BIN)/rev-mc \
		$(HOST_BIN)/tee-mc \
		$(HOST_BIN)/od-mc \
		$(HOST_BIN)/xxd-mc \
		$(HOST_BIN)/hexdump-mc \
		$(HOST_BIN)/aes128-mc \
		$(HOST_BIN)/yes-mc \
		$(HOST_BIN)/seq-mc \
		$(HOST_BIN)/sleep-mc \
		$(HOST_BIN)/time-mc \
		$(HOST_BIN)/kill-mc \
		$(HOST_BIN)/chown-mc \
		$(HOST_BIN)/ln-mc \
		$(HOST_BIN)/ls-mc \
		$(HOST_BIN)/touch-mc \
		$(HOST_BIN)/mkdir-mc \
		$(HOST_BIN)/rmdir-mc \
		$(HOST_BIN)/mv-mc \
		$(HOST_BIN)/rm-mc \
		$(HOST_BIN)/cp-mc
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/true.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/true-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/false.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/false-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/echo.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/echo-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/cat.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/cat-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/env.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/env-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/which.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/which-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/nproc.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/nproc-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/readlink.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/readlink-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/stat.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/stat-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/xargs.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/xargs-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/cmp.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/cmp-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/diff.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/diff-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/printf.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/printf-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/date.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/date-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/expr.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/expr-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/grep.c core/mc_io.c core/mc_str.c core/mc_fmt.c core/mc_regex.c -o $(HOST_BIN)/grep-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/sed.c core/mc_io.c core/mc_str.c core/mc_fmt.c core/mc_regex.c -o $(HOST_BIN)/sed-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/basename.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/basename-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/dirname.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/dirname-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/whoami.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/whoami-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/pwd.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/pwd-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/hostname.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/hostname-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/id.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/id-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/uname.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/uname-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/head.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/head-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/tail.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/tail-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/wc.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/wc-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/tr.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/tr-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/cut.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/cut-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/uniq.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/uniq-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/paste.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/paste-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/nl.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/nl-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/sort.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/sort-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/rev.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/rev-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/tee.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/tee-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/od.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/od-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/xxd.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/xxd-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/hexdump.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/hexdump-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/aes128.c core/mc_io.c core/mc_str.c core/mc_aes.c -o $(HOST_BIN)/aes128-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/yes.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/yes-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/seq.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/seq-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/sleep.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/sleep-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/time.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/time-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/kill.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/kill-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/chown.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/chown-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/ln.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/ln-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/ls.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/ls-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/touch.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/touch-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/mkdir.c core/mc_io.c core/mc_str.c core/mc_fmt.c -o $(HOST_BIN)/mkdir-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/rmdir.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/rmdir-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/mv.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/mv-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/rm.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/rm-mc >/dev/null
	@$(HOST_BIN)/monacc --target aarch64-darwin -I core tools/cp.c core/mc_io.c core/mc_str.c -o $(HOST_BIN)/cp-mc >/dev/null
	@test -x $(HOST_BIN)/true-mc && $(HOST_BIN)/true-mc
	@rc=0; $(HOST_BIN)/false-mc || rc=$$?; test $$rc -eq 1
	@test "$$($(HOST_BIN)/echo-mc -n hello)" = "hello"
	@tmpfile="$$(mktemp /tmp/monacc-cat.XXXXXX)"; \
		echo hi > "$$tmpfile"; \
		test "$$($(HOST_BIN)/cat-mc "$$tmpfile")" = "hi"; \
		rm -f "$$tmpfile"
	@test "$$($(HOST_BIN)/env-mc -i FOO=bar | grep -E '^FOO=bar$$' | head -n 1)" = "FOO=bar"
	@out="$$($(HOST_BIN)/which-mc sh | head -n 1)"; test -n "$$out"
	@out="$$($(HOST_BIN)/nproc-mc)"; echo "$$out" | grep -Eq '^[0-9]+$$'; test "$$out" -ge 1
	@tmpdir="$$(mktemp -d /tmp/monacc-readlinkstat.XXXXXX)"; \
		echo hi > "$$tmpdir/f"; \
		ln -s f "$$tmpdir/l"; \
		test "$$($(HOST_BIN)/readlink-mc "$$tmpdir/l")" = "f"; \
		out="$$($(HOST_BIN)/stat-mc "$$tmpdir/f" | head -n 1)"; \
		echo "$$out" | grep -q "type=reg"; \
		echo "$$out" | grep -q "size=3"; \
		rm -rf "$$tmpdir"
	@test "$$($(HOST_SH) -c 'printf "a\\nb\\n" | "'"$(HOST_BIN)/xargs-mc"'" -- /bin/echo')" = "a b"
	@tmpdir="$$(mktemp -d /tmp/monacc-cmpdiff.XXXXXX)"; \
		printf 'a\n' > "$$tmpdir/a"; \
		printf 'a\n' > "$$tmpdir/b"; \
		$(HOST_BIN)/cmp-mc -s "$$tmpdir/a" "$$tmpdir/b"; \
		printf 'b\n' > "$$tmpdir/b"; \
		rc=0; $(HOST_BIN)/cmp-mc -s "$$tmpdir/a" "$$tmpdir/b" >/dev/null 2>&1 || rc=$$?; test $$rc -eq 1; \
		out="$$($(HOST_BIN)/diff-mc "$$tmpdir/a" "$$tmpdir/b" || true)"; \
		echo "$$out" | grep -q "^diff: line 1"; \
		rm -rf "$$tmpdir"
	@test "$$($(HOST_BIN)/printf-mc '%05d' 7)" = "00007"
	@test "$$($(HOST_BIN)/printf-mc 'hi\n')" = "hi"
	@test "$$($(HOST_BIN)/expr-mc 1 + 2)" = "3"
	@rc=0; $(HOST_BIN)/expr-mc 0 >/dev/null 2>&1 || rc=$$?; test $$rc -eq 1
	@out="$$($(HOST_BIN)/date-mc +%Y)"; echo "$$out" | grep -Eq '^[0-9]{4}$$'
	@tmpfile="$$(mktemp /tmp/monacc-grep.XXXXXX)"; \
		printf 'a\nxb\nAx\n' > "$$tmpfile"; \
		test "$$($(HOST_BIN)/grep-mc -n x "$$tmpfile" | head -n 1)" = "2:xb"; \
		test "$$($(HOST_BIN)/grep-mc -i -n ax "$$tmpfile" | head -n 1)" = "3:Ax"; \
		rm -f "$$tmpfile"
	@tmpfile="$$(mktemp /tmp/monacc-sed.XXXXXX)"; \
		printf 'foo\nbar\n' > "$$tmpfile"; \
		test "$$($(HOST_BIN)/sed-mc -e 's/o/O/g' "$$tmpfile")" = "$$(printf 'fOO\nbar')"; \
		rm -f "$$tmpfile"
	@test "$$($(HOST_BIN)/basename-mc /usr/bin/ls)" = "ls"
		@test "$$( $(HOST_BIN)/basename-mc /usr/bin/ls s)" = "l"
	@test "$$($(HOST_BIN)/dirname-mc /usr/bin/ls)" = "/usr/bin"
	@test "$$($(HOST_BIN)/dirname-mc a/b)" = "a"
	@test "$$($(HOST_BIN)/whoami-mc)" = "$$($(HOST_SH) -c 'id -u')"
	@test "$$($(HOST_BIN)/pwd-mc)" = "$$($(HOST_SH) -c 'pwd')"
	@test "$$($(HOST_BIN)/hostname-mc)" = "$$($(HOST_SH) -c 'hostname')"
	@test "$$($(HOST_BIN)/id-mc -u)" = "$$($(HOST_SH) -c 'id -u')"
	@test "$$($(HOST_BIN)/id-mc -g)" = "$$($(HOST_SH) -c 'id -g')"
	@test "$$($(HOST_BIN)/uname-mc -s)" = "$$($(HOST_SH) -c 'uname -s')"
	@test "$$($(HOST_BIN)/uname-mc -m)" = "$$($(HOST_SH) -c 'uname -m')"
	@tmpfile="$$(mktemp /tmp/monacc-headtailwc.XXXXXX)"; \
		printf '1\n2\n3\n4\n5\n' > "$$tmpfile"; \
		test "$$($(HOST_BIN)/head-mc -n 1 "$$tmpfile")" = "1"; \
		test "$$($(HOST_BIN)/tail-mc -n 1 "$$tmpfile")" = "5"; \
		test "$$($(HOST_BIN)/wc-mc -l "$$tmpfile" | cut -d' ' -f1)" = "5"; \
		rm -f "$$tmpfile"
	@tmpfile="$$(mktemp /tmp/monacc-trcutuniq.XXXXXX)"; \
		printf 'aBc\n' > "$$tmpfile"; \
		test "$$($(HOST_BIN)/tr-mc a-z A-Z < "$$tmpfile")" = "ABC"; \
		printf 'abc,def,ghi\n' > "$$tmpfile"; \
		test "$$($(HOST_BIN)/cut-mc -d, -f2 "$$tmpfile")" = "def"; \
		printf 'a\na\nb\nb\n' > "$$tmpfile"; \
		test "$$($(HOST_BIN)/uniq-mc "$$tmpfile")" = "$$(printf 'a\nb')"; \
		rm -f "$$tmpfile"
	@tmpdir="$$(mktemp -d /tmp/monacc-sortpasteln.XXXXXX)"; \
		printf 'b\na\n' > "$$tmpdir/sort_in"; \
		test "$$($(HOST_BIN)/sort-mc "$$tmpdir/sort_in")" = "$$(printf 'a\nb')"; \
		printf 'a\nb\n' > "$$tmpdir/p1"; \
		printf 'c\nd\n' > "$$tmpdir/p2"; \
		test "$$($(HOST_BIN)/paste-mc "$$tmpdir/p1" "$$tmpdir/p2")" = "$$(printf 'a\tc\nb\td')"; \
		printf 'x\ny\n' > "$$tmpdir/nl_in"; \
		test "$$($(HOST_BIN)/nl-mc "$$tmpdir/nl_in")" = "$$(printf '     1\tx\n     2\ty')"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-revteeod.XXXXXX)"; \
		printf 'abc\nxy\n' > "$$tmpdir/rev_in"; \
		test "$$($(HOST_BIN)/rev-mc < "$$tmpdir/rev_in")" = "$$(printf 'cba\nyx')"; \
		printf 'hello\n' | $(HOST_BIN)/tee-mc "$$tmpdir/tee_out" >/dev/null; \
		test "$$($(HOST_SH) -c 'cat "'"$$tmpdir"'"/tee_out')" = "hello"; \
		test "$$($(HOST_BIN)/od-mc -An < "$$tmpdir/tee_out" | head -n 1 | tr -s ' ')" = " 150 145 154 154 157 012"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-xxdhexdump.XXXXXX)"; \
		printf 'ABC' > "$$tmpdir/in"; \
		out="$$($(HOST_BIN)/xxd-mc "$$tmpdir/in")"; \
		echo "$$out" | grep -q "^00000000:"; \
		echo "$$out" | grep -q "41 42 43"; \
		out="$$($(HOST_BIN)/hexdump-mc "$$tmpdir/in")"; \
		echo "$$out" | grep -q "^0000000000000000"; \
		echo "$$out" | grep -q "41 42 43"; \
		echo "$$out" | grep -q "\\|ABC"; \
		rm -rf "$$tmpdir"
	@test "$$($(HOST_BIN)/aes128-mc --fips197 | head -n 1)" = "69c4e0d86a7b0430d8cdb78070b4c55a"
	@$(HOST_BIN)/yes-mc | head -n 1 >/dev/null
	@test "$$($(HOST_BIN)/seq-mc 3 | wc -l | tr -d ' ')" = "3"
	@test "$$($(HOST_BIN)/seq-mc 3 | head -n 1)" = "1"
	@test "$$($(HOST_BIN)/seq-mc 3 | tail -n 1)" = "3"
	@$(HOST_BIN)/sleep-mc 0
	@$(HOST_BIN)/time-mc -- $(HOST_BIN)/true-mc >/dev/null
	@test "$$($(HOST_BIN)/kill-mc -l | head -n 1)" = "1"
	@rc=0; $(HOST_BIN)/chown-mc 0:0 . >/dev/null 2>&1 || rc=$$?; test $$rc -ne 0
	@tmpdir="$$(mktemp -d /tmp/monacc-ln.XXXXXX)"; \
		echo hi > "$$tmpdir/src"; \
		$(HOST_BIN)/ln-mc -f "$$tmpdir/src" "$$tmpdir/dst"; \
		test -e "$$tmpdir/dst"; \
		$(HOST_BIN)/ln-mc -sf "src" "$$tmpdir/sym"; \
		test -L "$$tmpdir/sym"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-ls.XXXXXX)"; \
		echo hi > "$$tmpdir/file"; \
		mkdir "$$tmpdir/sub"; \
		out="$$($(HOST_BIN)/ls-mc "$$tmpdir")"; \
		echo "$$out" | grep -q "^file$$"; \
		echo "$$out" | grep -q "^sub$$"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-touch.XXXXXX)"; \
		$(HOST_BIN)/touch-mc "$$tmpdir/a"; \
		test -f "$$tmpdir/a"; \
		sleep 1; \
		$(HOST_BIN)/touch-mc "$$tmpdir/a"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-mkdir.XXXXXX)"; \
		$(HOST_BIN)/mkdir-mc -p "$$tmpdir/a/b/c"; \
		test -d "$$tmpdir/a/b/c"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-rmdir.XXXXXX)"; \
		mkdir -p "$$tmpdir/a/b/c"; \
		$(HOST_BIN)/rmdir-mc "$$tmpdir/a/b/c"; \
		test ! -e "$$tmpdir/a/b/c"; \
		mkdir -p "$$tmpdir/x/y/z"; \
		$(HOST_BIN)/rmdir-mc -p "$$tmpdir/x/y/z"; \
		test ! -e "$$tmpdir/x"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-mv.XXXXXX)"; \
		echo hi > "$$tmpdir/a"; \
		$(HOST_BIN)/mv-mc "$$tmpdir/a" "$$tmpdir/b"; \
		test -f "$$tmpdir/b"; \
		mkdir -p "$$tmpdir/d1"; \
		$(HOST_BIN)/mv-mc "$$tmpdir/d1" "$$tmpdir/d2"; \
		test -d "$$tmpdir/d2"; \
		rm -rf "$$tmpdir"
	@if test "x$(DARWIN_NATIVE_MATRIX)" = "x1"; then \
		echo "==> Matrix: compile all tools (aarch64-darwin)"; \
		$(HOST_SH) -c './scripts/darwin-native-matrix.sh'; \
		echo "Matrix report: bin-host/darwin-native-matrix.md"; \
	fi
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-rm.XXXXXX)"; \
		echo hi > "$$tmpdir/a"; \
		$(HOST_BIN)/rm-mc "$$tmpdir/a"; \
		test ! -e "$$tmpdir/a"; \
		mkdir -p "$$tmpdir/d1/d2"; \
		$(HOST_BIN)/rm-mc -r "$$tmpdir/d1"; \
		test ! -e "$$tmpdir/d1"; \
		rm -rf "$$tmpdir"
	@tmpdir="$$(mktemp -d /tmp/monacc-cp.XXXXXX)"; \
		echo hi > "$$tmpdir/a"; \
		$(HOST_BIN)/cp-mc "$$tmpdir/a" "$$tmpdir/b"; \
		test "$$($(HOST_SH) -c 'cat "'"$$tmpdir"'"/b')" = "hi"; \
		rm -rf "$$tmpdir"
	@echo "Native tools smoke complete"
	@rm -f $(HOST_BIN)/ret42_mul
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_mul.c -o $(HOST_BIN)/ret42_mul >/dev/null
	@test -x $(HOST_BIN)/ret42_mul
	@rc=0; $(HOST_BIN)/ret42_mul || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_divmod
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_divmod.c -o $(HOST_BIN)/ret42_divmod >/dev/null
	@test -x $(HOST_BIN)/ret42_divmod
	@rc=0; $(HOST_BIN)/ret42_divmod || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_land_lor
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_land_lor.c -o $(HOST_BIN)/ret42_land_lor >/dev/null
	@test -x $(HOST_BIN)/ret42_land_lor
	@rc=0; $(HOST_BIN)/ret42_land_lor || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_bitwise
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_bitwise.c -o $(HOST_BIN)/ret42_bitwise >/dev/null
	@test -x $(HOST_BIN)/ret42_bitwise
	@rc=0; $(HOST_BIN)/ret42_bitwise || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_shift
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_shift.c -o $(HOST_BIN)/ret42_shift >/dev/null
	@test -x $(HOST_BIN)/ret42_shift
	@rc=0; $(HOST_BIN)/ret42_shift || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_not_bnot
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_not_bnot.c -o $(HOST_BIN)/ret42_not_bnot >/dev/null
	@test -x $(HOST_BIN)/ret42_not_bnot
	@rc=0; $(HOST_BIN)/ret42_not_bnot || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_cond
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_cond.c -o $(HOST_BIN)/ret42_cond >/dev/null
	@test -x $(HOST_BIN)/ret42_cond
	@rc=0; $(HOST_BIN)/ret42_cond || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_index_global
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_index_global.c -o $(HOST_BIN)/ret42_index_global >/dev/null
	@test -x $(HOST_BIN)/ret42_index_global
	@rc=0; $(HOST_BIN)/ret42_index_global || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_ptr_arith
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_ptr_arith.c -o $(HOST_BIN)/ret42_ptr_arith >/dev/null
	@test -x $(HOST_BIN)/ret42_ptr_arith
	@rc=0; $(HOST_BIN)/ret42_ptr_arith || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_index_store
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_index_store.c -o $(HOST_BIN)/ret42_index_store >/dev/null
	@test -x $(HOST_BIN)/ret42_index_store
	@rc=0; $(HOST_BIN)/ret42_index_store || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_char_signext
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_char_signext.c -o $(HOST_BIN)/ret42_char_signext >/dev/null
	@test -x $(HOST_BIN)/ret42_char_signext
	@rc=0; $(HOST_BIN)/ret42_char_signext || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_uchar_zeroext
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_uchar_zeroext.c -o $(HOST_BIN)/ret42_uchar_zeroext >/dev/null
	@test -x $(HOST_BIN)/ret42_uchar_zeroext
	@rc=0; $(HOST_BIN)/ret42_uchar_zeroext || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_short_signext
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_short_signext.c -o $(HOST_BIN)/ret42_short_signext >/dev/null
	@test -x $(HOST_BIN)/ret42_short_signext
	@rc=0; $(HOST_BIN)/ret42_short_signext || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_ushort_zeroext
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_ushort_zeroext.c -o $(HOST_BIN)/ret42_ushort_zeroext >/dev/null
	@test -x $(HOST_BIN)/ret42_ushort_zeroext
	@rc=0; $(HOST_BIN)/ret42_ushort_zeroext || rc=$$?; test $$rc -eq 42
	@rm -f $(HOST_BIN)/ret42_uchar_global_zeroext
	@$(HOST_BIN)/monacc --target aarch64-darwin examples/ret42_uchar_global_zeroext.c -o $(HOST_BIN)/ret42_uchar_global_zeroext >/dev/null
	@test -x $(HOST_BIN)/ret42_uchar_global_zeroext
	@rc=0; $(HOST_BIN)/ret42_uchar_global_zeroext || rc=$$?; test $$rc -eq 42
	@echo "Native smoke complete"

darwin-net-smoke: darwin-tools
	@echo "==> Smoke: macOS hosted networking"
	@test -x $(HOST_BIN)/tcp6
	@$(HOST_BIN)/tcp6 -W 5000 2001:4860:4860::8888 53
	@if test -x $(HOST_BIN)/wtf; then \
		$(HOST_BIN)/wtf -W 5000 Google >/dev/null; \
	fi
	@echo "Net smoke complete"

