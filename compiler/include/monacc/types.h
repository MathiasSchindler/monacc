#pragma once

// Types Module (types.h)
// ======================
//
// Fundamental type system for the monacc compiler.
// Part of Phase 3 of the monacc compiler structural rebase.
//
// This module defines:
// - BaseType enum: Primitive C types supported by the compiler
// - Type representation utilities

#include "mc.h"

// Forward declaration for Program (defined in ast.h)
typedef struct Program Program;

// Base types supported by the compiler
typedef enum {
    BT_INT = 0,
    BT_CHAR = 1,
    BT_SHORT = 2,
    BT_LONG = 3,
    BT_FLOAT = 4,
    BT_VOID = 5,
    BT_STRUCT = 6,
} BaseType;
