# Removing `ld`: plan for a minimal internal linker

Date: 2025-12-16

This document sketches a practical plan to eliminate the external linker (`ld`) by implementing a **minimal ELF64 linker** inside monacc.

The goal is **not** to re-create GNU ld. The goal is to link the very specific kind of programs monacc produces today:

- Linux x86_64 SysV
- Static, syscall-only binaries
- No libc, no shared libraries
- Output typically uses a small set of sections and relocations
- Build system already prefers internal `.o` emission (`--emit-obj`)

---

## Guiding principles

1. **Constrain the problem aggressively.**
   - Only Linux x86_64.
   - Only relocatable inputs produced by monacc itself (at least at first).
   - Only static final executables.
   - No dynamic loader, no shared libs, no PIE (initially).

2. **Make progress in narrow, testable slices.**
   - Implement one relocation kind at a time.
   - Keep “known-good external ld” as the oracle during bring-up.

3. **Keep the output layout simple and explicit.**
   - One PT_LOAD RX segment for `.text`+`.rodata`.
   - One PT_LOAD RW segment for `.data`.
   - `.bss` as `p_memsz > p_filesz` (zero-fill) in RW segment.

4. **Prefer correctness over cleverness.**
   - Correct relocations and symbol resolution first.
   - Size tuning (`--gc-sections`, page sizing) later.

5. **Design for observability.**
   - Always support a debug mode that keeps section headers, symbols, and relocation traces.
   - Add a “link map” dump early (addresses, sizes, symbol placements).

6. **Keep an escape hatch.**
   - Even after internal linking exists, keep `--ld <path>` or a build toggle until internal linking is battle-tested.

---

## What the minimal linker must do (scope)

### Inputs

- One or more ELF64 relocatable objects (`ET_REL`).
- Produced by monacc’s internal assembler/object writer (`--emit-obj`).

### Outputs

- ELF64 executable (`ET_EXEC`) suitable for Linux kernel loading.
- Correct entry point (`e_entry`) to `_start`.

### Core responsibilities

1. **Parse ELF relocatable objects**
   - ELF header, section headers, section data
   - `.symtab` and `.strtab`
   - relocation sections (`.rela.*`)

2. **Build a unified symbol table**
   - Collect definitions and references across all inputs
   - Resolve `STB_LOCAL` vs `STB_GLOBAL`
   - Error on unresolved required symbols

3. **Lay out output sections/segments**
   - Compute final VAs and file offsets for each output chunk
   - Respect alignment

4. **Apply relocations**
   - Patch code/data locations according to relocation type semantics
   - Validate overflow/fit (e.g., 32-bit PC-relative)

5. **Write output ELF**
   - ELF header + program headers (PT_LOAD)
   - Segment data


---

## Architecture: proposed internal API shape

A minimal linker can live as a separate module (suggested file name: `compiler/monacc_link.c` + `compiler/monacc_link.h`) and be invoked by monacc when producing final executables.

Recommended conceptual structures:

- `InputObj`
  - raw bytes
  - parsed sections (name, type, flags, alignment, data slice)
  - parsed symbols (name, bind/type, defined?, shndx, value, size)
  - parsed relocations (offset, type, symbol index/name, addend)

- `OutputLayout`
  - output segments (RX, RW)
  - output section-like ranges (text/rodata/data/bss)
  - mapping from (input section + offset) → (output VA + file offset)

- `GlobalSym`
  - name
  - resolved definition: (input, section, value)
  - final VA

- `RelocWorkItem`
  - target: output file offset
  - type
  - symbol name
  - addend
  - place (P)

Key property: relocations should be applied against the **final output image buffer** using computed symbol VAs.

---

## Minimal feature set (v1)

Start with the smallest set that can link monacc-style single-file outputs, then expand.

### Sections to support

- `.text*` (executable)
- `.rodata*` (read-only)
- `.data*` (read-write, initialized)
- `.bss*` (read-write, zero-fill; comes from `SHT_NOBITS`)

You can treat section name prefixes as categories:

- `.text` / `.text.<fn>` → TEXT
- `.rodata` / `.rodata.<x>` → RODATA
- `.data` / `.data.<x>` → DATA
- `.bss` / `.bss.<x>` → BSS

### Relocations to support first

Based on current monacc output patterns, the likely initial set is:

- `R_X86_64_PC32` — 32-bit signed PC-relative relocations (common for RIP-relative addressing)
- `R_X86_64_PLT32` — treat like `PC32` in static link (call/jmp rel32)

Then expand to:

- `R_X86_64_32` / `R_X86_64_32S` (if they appear)
- `R_X86_64_64` (absolute 64-bit)

If possible, instrument `--emit-obj` tests to list relocation types encountered to keep the plan grounded.

---

## Step-by-step plan with tests

### Step 0 — Add a “link backend” switch (plumbing)

**Goal:** Make it easy to toggle between external `ld` and internal link mode.

- Add a new flag: `--link-internal` (or reuse a Makefile toggle like `LINKER=internal`).
- Keep default as external `ld` until Step 4+ is stable.

**Tests**
- Ensure `--link-internal` is parsed and errors clearly if not implemented.


### Step 1 — Read and validate ELF64 `ET_REL`

**Goal:** Parse monacc-produced `.o` reliably.

- Implement parsing for:
  - ELF header
  - section headers
  - `.shstrtab` (for section names)
  - `.symtab` + `.strtab`
  - `.rela.*` sections

**Tests**
- Add a test script that compiles a tiny program with `--emit-obj -c` and then runs a new monacc subcommand or debug flag that dumps:
  - section list
  - symbol count and a few key symbols
  - relocation count and types
- Golden-file style checks are OK (stable output format).


### Step 2 — Single-object “link” without relocations

**Goal:** Produce an `ET_EXEC` that runs for the trivial case with no externals and no symbolic relocations.

- Hard-code minimal output:
  - one RX segment containing `.text`
  - entry point set to `_start`
- This will likely work only for “fully resolved” code (rare), but it proves ELF writing.

**Tests**
- A purpose-built example that contains no relocations (or as few as possible).
- Run and check exit code.


### Step 3 — Implement symbol resolution + `PC32` relocation

**Goal:** Link typical monacc outputs.

- Build global symbol table:
  - allow multiple locals
  - detect duplicate globals (error unless one is undefined/weak)
- Compute final VAs for all defined symbols.
- Apply relocations:

For `R_X86_64_PC32` / `R_X86_64_PLT32`:

$$
\text{write32}(P) \leftarrow (S + A) - P
$$

Where:
- $S$ is the symbol VA
- $A$ is the addend from RELA
- $P$ is the place VA of the relocation field

Validate signed 32-bit fit.

**Tests**
- Link and run a representative subset of existing examples (start with 3–5).
- Add a regression that specifically checks RIP-relative addressing into `.bss` and `.data`.
  - (These were historically sensitive when bringing up `--emit-obj`.)


### Step 4 — Multi-object linking (multiple `.o` inputs)

**Goal:** Replace external `ld` for monacc’s primary use case: multiple `.c` inputs.

- monacc today can compile multiple `.c` inputs into one binary; internally it may produce multiple `.o`.
- Internal linker must accept N inputs, resolve cross-object symbols, and lay out combined sections.

**Tests**
- Add a test that compiles two C files that call into each other.
- Compare output behavior vs external ld (exit code + maybe output).


### Step 5 — Support DATA/BSS properly

**Goal:** Ensure correct initialization and zero-fill.

- DATA: bytes in file, mapped RW.
- BSS: contributes to RW segment `p_memsz` but not `p_filesz`.
- Ensure alignment matches expectations.

**Tests**
- Existing examples already cover:
  - static local init
  - global array stores
  - extern incomplete array / rodata blobs


### Step 6 — Optional: keep/strip section headers + symbols

**Goal:** Preserve the current “strip section headers for size” behavior, but keep a debug mode.

- In debug: emit section headers and maybe a minimal `.symtab`.
- In release: omit them (matching current monacc behavior).

**Tests**
- `--keep-shdr` (or similar) produces a file where `readelf -S` works.
- Default output still runs.


### Step 7 — Size optimizations and `--gc-sections` (later)

**Goal:** Replace the size wins currently coming from `ld --gc-sections`.

This is optional for “remove external ld” correctness, but likely needed to avoid regressions.

Simplest approach:
- Only include referenced `.text.<fn>` and `.rodata.<x>` sections.
- Build a reachability graph:
  - roots: `_start`, exported symbols
  - edges: relocations from kept sections

**Tests**
- Compare binary sizes vs external ld (allow small deltas initially).
- Ensure no functional regressions.

---

## Test strategy (recommended sequence)

1. **Unit-ish tests (parser/link map)**
   - Dump parsed inputs and compare to expected patterns.

2. **Relocation-focused tests**
   - Tiny programs that force exactly one relocation kind.

3. **Golden external-ld oracle tests**
   - For a handful of programs:
     - Build via internal link
     - Build via external ld
     - Compare observable behavior (exit status, output)

4. **Full `make test` gating**
   - Once internal link passes a meaningful subset, gate it behind a toggle.
   - When it matches or exceeds external ld reliability, flip the default.

---

## Helpful reference knowledge (x86_64 + ELF)

- **RIP-relative addressing** on x86_64 uses a signed 32-bit displacement relative to the next instruction.
- With RELA relocations, the addend is stored explicitly in the relocation entry (`r_addend`).
- A minimal static executable can be as small as:
  - ELF header
  - Program header table (2 PT_LOADs)
  - segment bytes
- Section headers are not required by the Linux loader (monacc already strips them for size).

---

## Risks and common pitfalls

- **Relocation addend conventions:** mixing “place-relative” semantics with stored addends incorrectly is the #1 way to get subtle runtime misbehavior.
- **Alignment/offset mismatches:** if you compute VAs and file offsets with different padding rules, relocations will be wrong.
- **Overflow bugs:** `PC32` must fit signed 32-bit; failures should be clear errors.
- **Permissions (RWX):** keep RX and RW segments separate to avoid RWX warnings and improve safety.

---

## Definition of “done” (for ld removal)

- `make test` passes with internal link enabled for:
  - tools
  - all examples
  - selfhost tests
- Build no longer shells out to external `ld` in the default configuration.
- External `ld` remains available behind a flag for a while as a fallback.
