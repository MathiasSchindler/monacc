#pragma once

// Minimal stdarg stub for monacc self-hosting probes.
// This is only meant to get monacc through parsing/typechecking.

typedef void *va_list;

// monacc's preprocessor does not support function-like macros, so provide
// these as static functions to avoid unresolved references.
static void va_start(va_list ap, const char *last) {
	(void)ap;
	(void)last;
}

static void va_end(va_list ap) {
	(void)ap;
}
