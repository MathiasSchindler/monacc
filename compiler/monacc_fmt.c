#include "monacc.h"

// Minimal formatting helpers to reduce reliance on stdio formatting.

__attribute__((format(printf, 1, 2)))
void errf(const char *fmt, ...) {
    // Size-win mode: avoid pulling in printf-style formatting.
    // Keep call sites intact (arguments are ignored) but print the format string literally.
    xwrite_best_effort(2, fmt, mc_strlen(fmt));
}
