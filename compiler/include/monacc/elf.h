#pragma once

// ELF Object File Module (elf.h)
// ===============================
//
// This header defines the ELF object file interfaces for the monacc compiler,
// including object file assembly and debugging utilities.
//
// Part of the compiler structural rebase: ensuring frontend modules do not
// depend on backend, ELF, or linker details.

#include "mc_types.h"

// Forward declarations
typedef struct mc_compiler mc_compiler;

// ===== Object File Assembly =====

// Internal toolchain reduction: assemble monacc-emitted x86_64 assembly into
// an ELF64 relocatable object.
void assemble_x86_64_elfobj(mc_compiler *ctx, const char *asm_buf, mc_usize asm_len, const char *out_o_path);

// ===== ELF Debugging Utilities =====

// Dump ELF object file internals (symbols, sections, relocations)
void elfobj_dump(const char *path);

// Dump ELF section information
void elfsec_dump(const char *path);
