#include "mc.h"

#define CUT_MAX_FIELD 1024u
#define CUT_BITSET_U32S ((CUT_MAX_FIELD + 31u) / 32u)

static void cut_set_field(mc_u32 *bits, mc_u32 field) {
	if (field == 0 || field > CUT_MAX_FIELD) {
		return;
	}
	field -= 1u;
	bits[field / 32u] |= (1u << (field % 32u));
}

static int cut_field_selected(const mc_u32 *bits, mc_u32 field) {
	if (field == 0 || field > CUT_MAX_FIELD) {
		return 0;
	}
	field -= 1u;
	return (bits[field / 32u] >> (field % 32u)) & 1u;
}

static MC_NORETURN void cut_die_usage(const char *argv0) {
	mc_die_usage(argv0, "cut -f LIST [-d DELIM] [FILE...]");
}

static int cut_parse_u32_dec_range(const char *s, mc_u32 *out) {
	mc_u32 v = 0;
	if (mc_parse_u32_dec(s, &v) != 0) {
		return -1;
	}
	*out = v;
	return 0;
}

static void cut_parse_list_or_die(const char *argv0, const char *list, mc_u32 *bits) {
	// Supports: N, N-M, comma-separated.
	const char *p = list;
	if (!p || !*p) {
		cut_die_usage(argv0);
	}

	while (*p) {
		// Parse first number
		const char *a = p;
		while (*p && *p != ',' && *p != '-') p++;
		if (p == a) cut_die_usage(argv0);

		char tmp[32];
		mc_usize n = (mc_usize)(p - a);
		if (n >= sizeof(tmp)) cut_die_usage(argv0);
		for (mc_usize i = 0; i < n; i++) tmp[i] = a[i];
		tmp[n] = 0;

		mc_u32 start = 0;
		if (cut_parse_u32_dec_range(tmp, &start) != 0 || start == 0) {
			cut_die_usage(argv0);
		}

		if (*p == '-') {
			// Range
			p++;
			const char *b = p;
			while (*p && *p != ',') p++;
			if (p == b) cut_die_usage(argv0);

			mc_usize m = (mc_usize)(p - b);
			if (m >= sizeof(tmp)) cut_die_usage(argv0);
			for (mc_usize i = 0; i < m; i++) tmp[i] = b[i];
			tmp[m] = 0;

			mc_u32 end = 0;
			if (cut_parse_u32_dec_range(tmp, &end) != 0 || end == 0 || end < start) {
				cut_die_usage(argv0);
			}
			for (mc_u32 f = start; f <= end && f <= CUT_MAX_FIELD; f++) {
				cut_set_field(bits, f);
			}
		} else {
			cut_set_field(bits, start);
		}

		if (*p == ',') {
			p++;
			if (!*p) cut_die_usage(argv0);
		}
	}
}

struct cut_state {
	const mc_u32 *bits;
	mc_u8 delim;
	mc_u32 field;
	int at_field_start;
	int printing;
	int printed_any;
};

static void cut_state_reset_line(struct cut_state *st) {
	st->field = 1;
	st->at_field_start = 1;
	st->printing = 0;
	st->printed_any = 0;
}

static void cut_maybe_start_field(const char *argv0, struct cut_state *st) {
	if (!st->at_field_start) {
		return;
	}
	st->printing = cut_field_selected(st->bits, st->field);
	if (st->printing && st->printed_any) {
		mc_i64 w = mc_write_all(1, &st->delim, 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}
	st->at_field_start = 0;
}

static void cut_feed_byte(const char *argv0, struct cut_state *st, mc_u8 c) {
	if (c == (mc_u8)'\n') {
		mc_i64 w = mc_write_all(1, "\n", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
		cut_state_reset_line(st);
		return;
	}
	if (c == st->delim) {
		st->field++;
		st->at_field_start = 1;
		st->printing = 0;
		return;
	}

	cut_maybe_start_field(argv0, st);
	if (st->printing) {
		mc_i64 w = mc_write_all(1, &c, 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
		st->printed_any = 1;
	}
}

static int cut_fd(const char *argv0, mc_i32 fd, const mc_u32 *bits, mc_u8 delim) {
	mc_u8 buf[32768];
	struct cut_state st;
	st.bits = bits;
	st.delim = delim;
	cut_state_reset_line(&st);

	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}
		for (mc_i64 i = 0; i < r; i++) {
			cut_feed_byte(argv0, &st, buf[i]);
		}
	}
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "cut";

	mc_u32 bits[CUT_BITSET_U32S];
	for (mc_u32 j = 0; j < CUT_BITSET_U32S; j++) bits[j] = 0;

	const char *list = 0;
	mc_u8 delim = (mc_u8)'\t';

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || mc_streq(a, "-")) {
			break;
		}
		if (mc_streq(a, "-f")) {
			if (i + 1 >= argc) cut_die_usage(argv0);
			list = argv[i + 1];
			i++;
			continue;
		}
		if (mc_streq(a, "-d")) {
			if (i + 1 >= argc || !argv[i + 1]) cut_die_usage(argv0);
			const char *d = argv[i + 1];
			if (!d[0] || d[1]) cut_die_usage(argv0);
			delim = (mc_u8)d[0];
			i++;
			continue;
		}
		// Allow -fLIST
		if (a[1] == 'f' && a[2] != 0) {
			list = a + 2;
			continue;
		}
		// Allow -dX
		if (a[1] == 'd' && a[2] != 0) {
			if (a[3] != 0) cut_die_usage(argv0);
			delim = (mc_u8)a[2];
			continue;
		}
		cut_die_usage(argv0);
	}

	if (!list) {
		cut_die_usage(argv0);
	}
	cut_parse_list_or_die(argv0, list, bits);

	int had_error = 0;
	if (i >= argc) {
		(void)cut_fd(argv0, 0, bits, delim);
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) break;
		if (mc_streq(path, "-")) {
			(void)cut_fd(argv0, 0, bits, delim);
			continue;
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) {
			mc_print_errno(argv0, path, fd);
			had_error = 1;
			continue;
		}
		(void)cut_fd(argv0, (mc_i32)fd, bits, delim);
		(void)mc_sys_close((mc_i32)fd);
	}

	return had_error ? 1 : 0;
}
