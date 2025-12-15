#pragma once

// Self-hosting-only compatibility shims.
// Included via src/monacc.h when SELFHOST is defined.
//
// Note: monacc's preprocessor does not support function-like macros, so keep
// these as declarations/definitions instead of macro tricks.

static void __builtin_unreachable(void) {
	// Best-effort: in hosted builds this is a compiler builtin.
	// For self-host probes, doing nothing is fine.
}
