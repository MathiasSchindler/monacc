#include "mc.h"

static mc_usize printf_u64_dec(char *buf, mc_usize cap, mc_u64 v) {
	char tmp[32];
	mc_usize n = 0;
	if (v == 0) {
		if (cap) buf[0] = '0';
		return cap ? 1u : 0u;
	}
	while (v && n < sizeof(tmp)) {
		mc_u64 q = v / 10u;
		mc_u64 r = v - q * 10u;
		tmp[n++] = (char)('0' + (char)r);
		v = q;
	}
	// reverse
	mc_usize out = (n < cap) ? n : cap;
	for (mc_usize i = 0; i < out; i++) {
		buf[i] = tmp[n - 1 - i];
	}
	return n;
}

static mc_usize printf_u64_hex(char *buf, mc_usize cap, mc_u64 v) {
	char tmp[32];
	mc_usize n = 0;
	if (v == 0) {
		if (cap) buf[0] = '0';
		return cap ? 1u : 0u;
	}
	while (v && n < sizeof(tmp)) {
		mc_u8 d = (mc_u8)(v & 0xFu);
		tmp[n++] = (d < 10) ? (char)('0' + d) : (char)('a' + (d - 10));
		v >>= 4;
	}
	mc_usize out = (n < cap) ? n : cap;
	for (mc_usize i = 0; i < out; i++) {
		buf[i] = tmp[n - 1 - i];
	}
	return n;
}

static void printf_write_pad(const char *argv0, char ch, mc_u32 n) {
	char buf[64];
	for (mc_u32 i = 0; i < (mc_u32)sizeof(buf); i++) buf[i] = ch;
	while (n) {
		mc_u32 chunk = n;
		if (chunk > (mc_u32)sizeof(buf)) chunk = (mc_u32)sizeof(buf);
		mc_i64 w = mc_write_all(1, buf, (mc_usize)chunk);
		if (w < 0) mc_die_errno(argv0, "write", w);
		n -= chunk;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "printf";

	if (argc < 2) {
		mc_die_usage(argv0, "printf FORMAT [ARG...]");
	}

	int ai = 2;
	const char *fmt = argv[1] ? argv[1] : "";

	for (const char *p = fmt; *p; ) {
		char c = *p++;
		if (c == '\\') {
			char e = *p;
			if (!e) {
				char b = '\\';
				mc_i64 w = mc_write_all(1, &b, 1);
				if (w < 0) mc_die_errno(argv0, "write", w);
				break;
			}
			p++;
			char out = e;
			if (e == 'n') out = '\n';
			else if (e == 't') out = '\t';
			else if (e == '\\') out = '\\';
			mc_i64 w = mc_write_all(1, &out, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
			continue;
		}
		if (c != '%') {
			mc_i64 w = mc_write_all(1, &c, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
			continue;
		}

		char f = *p;
		if (!f) {
			char pc = '%';
			mc_i64 w = mc_write_all(1, &pc, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
			break;
		}

		// Parse flags/width/precision: %-05.2d
		int left = 0;
		int zero = 0;
		int prec_set = 0;
		mc_u32 width = 0;
		mc_u32 prec = 0;
		while (*p == '-' || *p == '0') {
			if (*p == '-') left = 1;
			else if (*p == '0') zero = 1;
			p++;
		}
		while (*p >= '0' && *p <= '9') {
			width = width * 10u + (mc_u32)(*p - '0');
			p++;
		}
		if (*p == '.') {
			prec_set = 1;
			p++;
			while (*p >= '0' && *p <= '9') {
				prec = prec * 10u + (mc_u32)(*p - '0');
				p++;
			}
			zero = 0; // precision overrides '0' padding
		}

		f = *p;
		if (!f) {
			char pc = '%';
			mc_i64 w = mc_write_all(1, &pc, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
			break;
		}
		p++;

		if (f == '%') {
			char pc = '%';
			mc_i64 w = mc_write_all(1, &pc, 1);
			if (w < 0) mc_die_errno(argv0, "write", w);
			continue;
		}

		int has_arg = (ai < argc && argv[ai]);
		const char *arg = has_arg ? argv[ai] : "";
		if (ai < argc) ai++;

		if (f == 's') {
			mc_usize n = mc_strlen(arg);
			if (prec_set && (mc_u32)n > prec) n = (mc_usize)prec;
			mc_u32 pad = (width > (mc_u32)n) ? (width - (mc_u32)n) : 0u;
			if (!left) printf_write_pad(argv0, ' ', pad);
			mc_i64 w = mc_write_all(1, arg, n);
			if (w < 0) mc_die_errno(argv0, "write", w);
			if (left) printf_write_pad(argv0, ' ', pad);
			continue;
		}
		if (f == 'c') {
			mc_u32 n = arg[0] ? 1u : 0u;
			mc_u32 pad = (width > n) ? (width - n) : 0u;
			if (!left) printf_write_pad(argv0, ' ', pad);
			if (arg[0]) {
				char out = arg[0];
				mc_i64 w = mc_write_all(1, &out, 1);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (left) printf_write_pad(argv0, ' ', pad);
			continue;
		}
		if (f == 'd') {
			mc_i64 v = 0;
			if (arg[0] && mc_parse_i64_dec(arg, &v) != 0) {
				mc_die_usage(argv0, "printf FORMAT [ARG...]");
			}
			int neg = (v < 0);
			mc_u64 mag = neg ? ((mc_u64)(-(v + 1)) + 1u) : (mc_u64)v;
			char digits[32];
			mc_usize nd = 0;
			if (prec_set && prec == 0u && mag == 0u) {
				nd = 0;
			} else {
				nd = printf_u64_dec(digits, sizeof(digits), mag);
			}
			mc_u32 zprec = 0;
			if (prec_set && (mc_u32)nd < prec) zprec = prec - (mc_u32)nd;
			mc_u32 core = (mc_u32)nd + zprec + (neg ? 1u : 0u);
			mc_u32 pad = (width > core) ? (width - core) : 0u;
			if (!left && !zero) printf_write_pad(argv0, ' ', pad);
			if (neg) {
				char m = '-';
				mc_i64 w = mc_write_all(1, &m, 1);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (!left && zero) printf_write_pad(argv0, '0', pad);
			printf_write_pad(argv0, '0', zprec);
			if (nd) {
				mc_i64 w = mc_write_all(1, digits, nd);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (left) printf_write_pad(argv0, ' ', pad);
			continue;
		}
		if (f == 'u') {
			mc_u64 v = 0;
			if (arg[0] && mc_parse_u64_dec(arg, &v) != 0) {
				mc_die_usage(argv0, "printf FORMAT [ARG...]");
			}
			char digits[32];
			mc_usize nd = 0;
			if (prec_set && prec == 0u && v == 0u) {
				nd = 0;
			} else {
				nd = printf_u64_dec(digits, sizeof(digits), v);
			}
			mc_u32 zprec = 0;
			if (prec_set && (mc_u32)nd < prec) zprec = prec - (mc_u32)nd;
			mc_u32 core = (mc_u32)nd + zprec;
			mc_u32 pad = (width > core) ? (width - core) : 0u;
			if (!left && !zero) printf_write_pad(argv0, ' ', pad);
			if (!left && zero) printf_write_pad(argv0, '0', pad);
			printf_write_pad(argv0, '0', zprec);
			if (nd) {
				mc_i64 w = mc_write_all(1, digits, nd);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (left) printf_write_pad(argv0, ' ', pad);
			continue;
		}
		if (f == 'x') {
			mc_u64 v = 0;
			if (arg[0] && mc_parse_u64_dec(arg, &v) != 0) {
				mc_die_usage(argv0, "printf FORMAT [ARG...]");
			}
			char digits[32];
			mc_usize nd = 0;
			if (prec_set && prec == 0u && v == 0u) {
				nd = 0;
			} else {
				nd = printf_u64_hex(digits, sizeof(digits), v);
			}
			mc_u32 zprec = 0;
			if (prec_set && (mc_u32)nd < prec) zprec = prec - (mc_u32)nd;
			mc_u32 core = (mc_u32)nd + zprec;
			mc_u32 pad = (width > core) ? (width - core) : 0u;
			if (!left && !zero) printf_write_pad(argv0, ' ', pad);
			if (!left && zero) printf_write_pad(argv0, '0', pad);
			printf_write_pad(argv0, '0', zprec);
			if (nd) {
				mc_i64 w = mc_write_all(1, digits, nd);
				if (w < 0) mc_die_errno(argv0, "write", w);
			}
			if (left) printf_write_pad(argv0, ' ', pad);
			continue;
		}

		mc_die_usage(argv0, "printf FORMAT [ARG...]");
	}

	return 0;
}
