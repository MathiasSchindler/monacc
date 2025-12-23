#pragma once

// Module Headers (monacc_modules.h)
// ==================================
//
// This header includes all the module-specific headers for the monacc compiler.
// Part of Phase 3 of the monacc compiler structural rebase: splitting the
// monolithic monacc.h into focused module headers.
//
// This provides a convenient single include point for code that needs access
// to multiple compiler modules.

#include "monacc/diag.h"
#include "monacc/token.h"
#include "monacc/ast.h"
#include "monacc/pp.h"
#include "monacc/backend.h"
#include "monacc/util.h"
