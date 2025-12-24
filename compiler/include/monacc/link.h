#pragma once

// Internal Linker Module (link.h)
// ================================
//
// This header defines the internal linker interfaces for the monacc compiler,
// enabling linking of object files into executables.
//
// Part of the compiler structural rebase: ensuring frontend modules do not
// depend on backend, ELF, or linker details.

#include "mc_types.h"

// ===== Internal Linker APIs =====

// Minimal internal linker (Step 2): link a single .o into an executable
// without relocations.
void link_internal_exec_single_obj(const char *obj_path, const char *out_path);

// Step 4: link multiple objects into a single executable.
void link_internal_exec_objs(const char **obj_paths, int nobj_paths, const char *out_path, int keep_shdr);
