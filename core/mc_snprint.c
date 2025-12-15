#include "mc.h"

typedef struct {
	char *dst;
	mc_usize cap;
	mc_usize pos; // number of bytes that would have been written (excluding NUL)
} McPrintBuf;

static void mpb_putc(McPrintBuf *b, char c) {
	if (b->cap && b->pos < b->cap - 1) b->dst[b->pos] = c;
	b->pos++;
}

static void mpb_puts(McPrintBuf *b, const char *s) {
	if (!s) s = "(null)";
	for (const char *p = s; *p; p++) mpb_putc(b, *p);
}

static void mpb_put_u64_dec(McPrintBuf *b, mc_u64 v) {
	char tmp[32];
	mc_usize n = 0;
	if (v == 0) {
		tmp[n++] = '0';
	} else {
		while (v > 0) {
			tmp[n++] = (char)('0' + (char)(v % 10));
			v /= 10;
		}
	}
	while (n--) mpb_putc(b, tmp[n]);
}

static void mpb_terminate(McPrintBuf *b) {
	if (!b->cap) return;
	mc_usize n = (b->pos < b->cap) ? b->pos : (b->cap - 1);
	b->dst[n] = 0;
}

int mc_snprint_cstr_cstr(char *dst, mc_usize cap, const char *a, const char *b) {
	McPrintBuf pb;
	pb.dst = dst;
	pb.cap = cap;
	pb.pos = 0;
	mpb_puts(&pb, a);
	mpb_puts(&pb, b);
	mpb_terminate(&pb);
	if (pb.pos > (mc_usize)MC_INT_MAX) return MC_INT_MAX;
	return (int)pb.pos;
}

int mc_snprint_cstr_u64_cstr(char *dst, mc_usize cap, const char *a, mc_u64 u, const char *b) {
	McPrintBuf pb;
	pb.dst = dst;
	pb.cap = cap;
	pb.pos = 0;
	mpb_puts(&pb, a);
	mpb_put_u64_dec(&pb, u);
	mpb_puts(&pb, b);
	mpb_terminate(&pb);
	if (pb.pos > (mc_usize)MC_INT_MAX) return MC_INT_MAX;
	return (int)pb.pos;
}

int mc_snprint_cstr_cstr_u64_cstr(char *dst, mc_usize cap, const char *a, const char *mid, mc_u64 u, const char *b) {
	McPrintBuf pb;
	pb.dst = dst;
	pb.cap = cap;
	pb.pos = 0;
	mpb_puts(&pb, a);
	mpb_puts(&pb, mid);
	mpb_put_u64_dec(&pb, u);
	mpb_puts(&pb, b);
	mpb_terminate(&pb);
	if (pb.pos > (mc_usize)MC_INT_MAX) return MC_INT_MAX;
	return (int)pb.pos;
}
