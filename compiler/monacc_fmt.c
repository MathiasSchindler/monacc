#include "monacc.h"

// Minimal formatting helpers to reduce reliance on stdio formatting.

__attribute__((format(printf, 1, 2)))
void errf(const char *fmt, ...) {
#ifdef SELFHOST
    xwrite_best_effort(2, fmt, mc_strlen(fmt));
#else
    va_list ap;
    va_start(ap, fmt);

    char stack_buf[1024];
    va_list ap2;
    va_copy(ap2, ap);
    int n = mc_vsnprintf(stack_buf, sizeof(stack_buf), fmt, ap2);
    va_end(ap2);

    if (n < 0) {
        va_end(ap);
        return;
    }

    if ((size_t)n < sizeof(stack_buf)) {
        xwrite_best_effort(2, stack_buf, (size_t)n);
        va_end(ap);
        return;
    }

    size_t need = (size_t)n + 1;
    char *heap_buf = (char *)monacc_malloc(need);
    if (!heap_buf) {
        xwrite_best_effort(2, stack_buf, sizeof(stack_buf) - 1);
        va_end(ap);
        return;
    }

    (void)mc_vsnprintf(heap_buf, need, fmt, ap);
    xwrite_best_effort(2, heap_buf, (size_t)n);
    monacc_free(heap_buf);

    va_end(ap);
#endif
}
