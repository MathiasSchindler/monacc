#include "mc.h"

// Hosted-only implementation.
#if !defined(MONACC) && !defined(SELFHOST)

// Minimal stdarg subset (avoid pulling in <stdarg.h>).
typedef __builtin_va_list va_list;
#define va_start(ap, last) __builtin_va_start(ap, last)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dest, src) __builtin_va_copy(dest, src)

typedef struct {
	char *dst;
	mc_usize cap;
	mc_usize pos; // number of bytes that would have been written (excluding NUL)
} FmtBuf;

static void fb_putc(FmtBuf *b, char c) {
	if (b->cap && b->pos < b->cap - 1) b->dst[b->pos] = c;
	b->pos++;
}

static void fb_puts(FmtBuf *b, const char *s) {
	if (!s) s = "(null)";
	for (const char *p = s; *p; p++) fb_putc(b, *p);
}

static void fb_putsn(FmtBuf *b, const char *s, mc_usize n) {
	if (!s) s = "(null)";
	for (mc_usize i = 0; i < n && s[i]; i++) fb_putc(b, s[i]);
}

static void fb_put_u64_dec(FmtBuf *b, mc_u64 v) {
	char tmp[32];
	mc_usize n = 0;
	do {
		tmp[n++] = (char)('0' + (char)(v % 10));
		v /= 10;
	} while (v);
	while (n--) fb_putc(b, tmp[n]);
}

static void fb_put_i64_dec(FmtBuf *b, mc_i64 v) {
	mc_u64 u;
	if (v < 0) {
		fb_putc(b, '-');
		u = (mc_u64)(-(v + 1));
		u += 1;
	} else {
		u = (mc_u64)v;
	}
	fb_put_u64_dec(b, u);
}

static void fb_put_u64_hex(FmtBuf *b, mc_u64 v, int upper) {
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	char tmp[32];
	mc_usize n = 0;
	do {
		tmp[n++] = digits[v & 0xF];
		v >>= 4;
	} while (v);
	while (n--) fb_putc(b, tmp[n]);
}

static void fb_terminate(FmtBuf *b) {
	if (!b->cap) return;
	mc_usize n = (b->pos < b->cap) ? b->pos : (b->cap - 1);
	b->dst[n] = 0;
}

int mc_vsnprintf(char *dst, mc_usize cap, const char *fmt, va_list ap) {
	FmtBuf b;
	b.dst = dst;
	b.cap = cap;
	b.pos = 0;

	for (const char *p = fmt; p && *p; ) {
		if (*p != '%') {
			fb_putc(&b, *p++);
			continue;
		}
		p++; // '%'
		if (*p == '%') {
			fb_putc(&b, '%');
			p++;
			continue;
		}

		// Consume flags
		for (;;) {
			char c = *p;
			if (c == '-' || c == '+' || c == ' ' || c == '#' || c == '0') {
				p++;
				continue;
			}
			break;
		}

		// Width
		if (*p == '*') {
			(void)va_arg(ap, int);
			p++;
		} else {
			while (*p >= '0' && *p <= '9') p++;
		}

		// Precision
		int precision = -1;
		if (*p == '.') {
			p++;
			if (*p == '*') {
				precision = va_arg(ap, int);
				p++;
			} else {
				precision = 0;
				while (*p >= '0' && *p <= '9') {
					precision = precision * 10 + (*p - '0');
					p++;
				}
			}
			if (precision < 0) precision = -1;
		}

		int lcount = 0;
		if (*p == 'l') {
			lcount++;
			p++;
			if (*p == 'l') {
				lcount++;
				p++;
			}
		}

		char spec = *p ? *p++ : 0;
		switch (spec) {
			case 's': {
				const char *s = va_arg(ap, const char *);
				if (precision >= 0) fb_putsn(&b, s, (mc_usize)precision);
				else fb_puts(&b, s);
				break;
			}
			case 'c': {
				int c = va_arg(ap, int);
				fb_putc(&b, (char)c);
				break;
			}
			case 'd':
			case 'i': {
				mc_i64 v;
				if (lcount >= 2) v = (mc_i64)va_arg(ap, long long);
				else if (lcount == 1) v = (mc_i64)va_arg(ap, long);
				else v = (mc_i64)va_arg(ap, int);
				fb_put_i64_dec(&b, v);
				break;
			}
			case 'u': {
				mc_u64 v;
				if (lcount >= 2) v = (mc_u64)va_arg(ap, unsigned long long);
				else if (lcount == 1) v = (mc_u64)va_arg(ap, unsigned long);
				else v = (mc_u64)va_arg(ap, unsigned);
				fb_put_u64_dec(&b, v);
				break;
			}
			case 'x':
			case 'X': {
				mc_u64 v;
				if (lcount >= 2) v = (mc_u64)va_arg(ap, unsigned long long);
				else if (lcount == 1) v = (mc_u64)va_arg(ap, unsigned long);
				else v = (mc_u64)va_arg(ap, unsigned);
				fb_put_u64_hex(&b, v, spec == 'X');
				break;
			}
			case 'p': {
				void *ptr = va_arg(ap, void *);
				fb_puts(&b, "0x");
				fb_put_u64_hex(&b, (mc_u64)(mc_uintptr)ptr, 0);
				break;
			}
			default:
				fb_puts(&b, "<?>" );
				break;
		}
	}

	fb_terminate(&b);
	if (b.pos > (mc_usize)MC_INT_MAX) return MC_INT_MAX;
	return (int)b.pos;
}

__attribute__((format(printf, 3, 4)))
int mc_snprintf(char *dst, mc_usize cap, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	int n = mc_vsnprintf(dst, cap, fmt, ap);
	va_end(ap);
	return n;
}

#endif
