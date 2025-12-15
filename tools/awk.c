#include "mc.h"

// Minimal awk subset:
// - Usage: awk [-F FS] 'PROGRAM' [FILE...]
// - PROGRAM forms supported:
//   1) { print }
//   2) { print ITEM[,ITEM...] }
//   3) /REGEX/ { print ... }
//   4) /REGEX/            (default action: print $0)
//   5) print ITEM[,ITEM...] (action without braces)
// - ITEM forms supported:
//   - $0, $1..$N
//   - NR, NF
//   - "string literal" with escapes: \n, \t, \\, \"
// - Regex subset (K&R): literals, ., *, ^, $, and backslash escape for literals.
// - FS: default whitespace (space/tab, runs collapse), or single-byte delimiter via -F.

enum awk_item_kind {
	AWK_ITEM_FIELD = 1,
	AWK_ITEM_NR = 2,
	AWK_ITEM_NF = 3,
	AWK_ITEM_STR = 4,
};

struct awk_item {
	enum awk_item_kind kind;
	mc_u32 field_index; // for AWK_ITEM_FIELD
	mc_u32 str_off;
	mc_u32 str_len;
};

struct awk_prog {
	int has_pattern;
	int pattern_kind; // 1=regex, 2=numeric
	char pattern[512];

	// numeric pattern: LHS OP RHS
	// LHS: $N, NR, NF
	int pat_lhs_kind; // 1=field, 2=NR, 3=NF
	mc_u32 pat_field_index;
	int pat_op; // 1==,2!=,3<,4<=,5>,6>=
	mc_i64 pat_rhs;

	int has_action;
	struct awk_item items[32];
	mc_u32 n_items;

	char str_pool[1024];
	mc_u32 str_pool_len;
};

static void awk_skip_spaces(const char **ps) {
	const char *s = *ps;
	while (*s && mc_is_space_ascii((mc_u8)*s)) s++;
	*ps = s;
}

static int awk_starts_with_kw(const char *s, const char *kw) {
	// matches keyword at s and ensures next char is not [A-Za-z0-9_]
	const char *p = s;
	const char *k = kw;
	while (*k) {
		if (*p != *k) return 0;
		p++;
		k++;
	}
	char n = *p;
	if ((n >= 'A' && n <= 'Z') || (n >= 'a' && n <= 'z') || (n >= '0' && n <= '9') || n == '_') return 0;
	return 1;
}

static int awk_parse_u32(const char **ps, mc_u32 *out) {
	return mc_parse_u32_dec_prefix(ps, out);
}

static int awk_parse_i64(const char **ps, mc_i64 *out) {
	return mc_parse_i64_dec_prefix(ps, out);
}

// --- Tiny regex matcher (K&R style)

static int awk_token_len(const char *re) {
	if (!re || !*re) return 0;
	if (re[0] == '\\' && re[1] != 0) return 2;
	return 1;
}

static int awk_token_matches(const char *token, char t) {
	if (!token || !*token) return 0;
	if (token[0] == '.') return t != 0;
	if (token[0] == '\\' && token[1] != 0) return t == token[1];
	return t == token[0];
}

static int awk_matchhere(const char *re, const char *text);

static int awk_matchstar(const char *token, const char *re_rest, const char *text) {
	const char *t = text;
	while (*t && awk_token_matches(token, *t)) t++;
	for (;;) {
		if (awk_matchhere(re_rest, t)) return 1;
		if (t == text) break;
		t--;
	}
	return 0;
}

static int awk_matchhere(const char *re, const char *text) {
	if (!re || re[0] == 0) return 1;
	if (re[0] == '$' && re[1] == 0) return *text == 0;
	int tlen = awk_token_len(re);
	if (tlen == 0) return 1;
	if (re[tlen] == '*') return awk_matchstar(re, re + tlen + 1, text);
	if (*text && awk_token_matches(re, *text)) return awk_matchhere(re + tlen, text + 1);
	return 0;
}

static int awk_match(const char *re, const char *text) {
	if (!re || !text) return 0;
	if (re[0] == '^') return awk_matchhere(re + 1, text);
	for (const char *t = text; ; t++) {
		if (awk_matchhere(re, t)) return 1;
		if (*t == 0) break;
	}
	return 0;
}

// --- Program parsing

static int awk_pool_add(struct awk_prog *p, const char *s, mc_u32 len, mc_u32 *out_off) {
	if (p->str_pool_len + len >= (mc_u32)sizeof(p->str_pool)) return -1;
	*out_off = p->str_pool_len;
	for (mc_u32 i = 0; i < len; i++) p->str_pool[p->str_pool_len++] = s[i];
	return 0;
}

static int awk_parse_string(struct awk_prog *p, const char **ps) {
	// Parses "..." and adds as AWK_ITEM_STR.
	const char *s = *ps;
	if (*s != '"') return -1;
	s++;
	char tmp[512];
	mc_u32 tlen = 0;
	while (*s) {
		char c = *s++;
		if (c == '"') break;
		if (c == '\\' && *s) {
			char e = *s++;
			if (e == 'n') c = '\n';
			else if (e == 't') c = '\t';
			else if (e == '"') c = '"';
			else if (e == '\\') c = '\\';
			else c = e;
		}
		if (tlen + 1 >= (mc_u32)sizeof(tmp)) return -1;
		tmp[tlen++] = c;
	}
	if (s[-1] != '"') return -1;

	if (p->n_items >= (mc_u32)(sizeof(p->items) / sizeof(p->items[0]))) return -1;
	mc_u32 off = 0;
	if (awk_pool_add(p, tmp, tlen, &off) != 0) return -1;
	p->items[p->n_items++] = (struct awk_item){ .kind = AWK_ITEM_STR, .str_off = off, .str_len = tlen };
	*ps = s;
	return 0;
}

static int awk_parse_item(struct awk_prog *p, const char **ps) {
	awk_skip_spaces(ps);
	const char *s = *ps;
	if (*s == '$') {
		s++;
		mc_u32 idx = 0;
		if (awk_parse_u32(&s, &idx) != 0) return -1;
		if (p->n_items >= (mc_u32)(sizeof(p->items) / sizeof(p->items[0]))) return -1;
		p->items[p->n_items++] = (struct awk_item){ .kind = AWK_ITEM_FIELD, .field_index = idx };
		*ps = s;
		return 0;
	}
	if (*s == '"') {
		return awk_parse_string(p, ps);
	}
	if (awk_starts_with_kw(s, "NR")) {
		if (p->n_items >= (mc_u32)(sizeof(p->items) / sizeof(p->items[0]))) return -1;
		p->items[p->n_items++] = (struct awk_item){ .kind = AWK_ITEM_NR };
		*ps = s + 2;
		return 0;
	}
	if (awk_starts_with_kw(s, "NF")) {
		if (p->n_items >= (mc_u32)(sizeof(p->items) / sizeof(p->items[0]))) return -1;
		p->items[p->n_items++] = (struct awk_item){ .kind = AWK_ITEM_NF };
		*ps = s + 2;
		return 0;
	}
	return -1;
}

static int awk_parse_print_list(struct awk_prog *p, const char **ps) {
	// Assumes current position is right after 'print'
	awk_skip_spaces(ps);
	const char *s = *ps;
	// Empty print list => print $0
	if (*s == 0 || *s == '}' ) {
		p->has_action = 1;
		return 0;
	}

	for (;;) {
		if (awk_parse_item(p, ps) != 0) return -1;
		awk_skip_spaces(ps);
		s = *ps;
		if (*s == ',') {
			s++;
			*ps = s;
			continue;
		}
		return 0;
	}
}

static int awk_parse_action(struct awk_prog *p, const char **ps, int require_closing_brace) {
	awk_skip_spaces(ps);
	const char *s = *ps;
	if (!awk_starts_with_kw(s, "print")) return -1;
	s += 5;
	*ps = s;
	p->has_action = 1;
	if (awk_parse_print_list(p, ps) != 0) return -1;
	awk_skip_spaces(ps);
	s = *ps;
	if (require_closing_brace) {
		if (*s != '}') return -1;
		s++;
		*ps = s;
	}
	return 0;
}

static int awk_parse_regex_between_slashes(const char **ps, char *out, mc_u32 out_sz) {
	// Parse /.../ with support for escaping \/ and \\.
	const char *s = *ps;
	if (*s != '/') return -1;
	s++;
	mc_u32 o = 0;
	while (*s) {
		char c = *s++;
		if (c == '/') {
			out[o] = 0;
			*ps = s;
			return 0;
		}
		if (c == '\\' && *s) {
			char n = *s++;
			// Keep escape in regex for matcher.
			if (o + 2 >= out_sz) return -1;
			out[o++] = '\\';
			out[o++] = n;
			continue;
		}
		if (o + 1 >= out_sz) return -1;
		out[o++] = c;
	}
	return -1;
}

static int awk_parse_op(const char **ps, int *out_op) {
	awk_skip_spaces(ps);
	const char *s = *ps;
	if (s[0] == '=' && s[1] == '=') {
		*out_op = 1;
		*ps = s + 2;
		return 0;
	}
	if (s[0] == '!' && s[1] == '=') {
		*out_op = 2;
		*ps = s + 2;
		return 0;
	}
	if (s[0] == '<' && s[1] == '=') {
		*out_op = 4;
		*ps = s + 2;
		return 0;
	}
	if (s[0] == '>' && s[1] == '=') {
		*out_op = 6;
		*ps = s + 2;
		return 0;
	}
	if (s[0] == '<') {
		*out_op = 3;
		*ps = s + 1;
		return 0;
	}
	if (s[0] == '>') {
		*out_op = 5;
		*ps = s + 1;
		return 0;
	}
	return -1;
}

static int awk_parse_numeric_pattern(struct awk_prog *out, const char **ps) {
	// pattern: ($N|NR|NF) OP INT
	awk_skip_spaces(ps);
	const char *s = *ps;
	out->pattern_kind = 2;
	out->has_pattern = 1;
	out->pat_lhs_kind = 0;
	out->pat_field_index = 0;
	out->pat_op = 0;
	out->pat_rhs = 0;

	if (*s == '$') {
		s++;
		mc_u32 idx = 0;
		if (awk_parse_u32(&s, &idx) != 0) return -1;
		out->pat_lhs_kind = 1;
		out->pat_field_index = idx;
		*ps = s;
	} else if (awk_starts_with_kw(s, "NR")) {
		out->pat_lhs_kind = 2;
		*ps = s + 2;
	} else if (awk_starts_with_kw(s, "NF")) {
		out->pat_lhs_kind = 3;
		*ps = s + 2;
	} else {
		return -1;
	}

	if (awk_parse_op(ps, &out->pat_op) != 0) return -1;
	awk_skip_spaces(ps);
	if (awk_parse_i64(ps, &out->pat_rhs) != 0) return -1;
	return 0;
}

static int awk_parse_program(const char *prog, struct awk_prog *out) {
	*out = (struct awk_prog){0};
	const char *s = prog;
	awk_skip_spaces(&s);
	if (*s == '/') {
		out->has_pattern = 1;
		out->pattern_kind = 1;
		if (awk_parse_regex_between_slashes(&s, out->pattern, (mc_u32)sizeof(out->pattern)) != 0) return -1;
		awk_skip_spaces(&s);
		if (*s == 0) {
			// Pattern only: default action.
			out->has_action = 0;
			return 0;
		}
		if (*s != '{') return -1;
		s++;
		if (awk_parse_action(out, &s, 1) != 0) return -1;
		awk_skip_spaces(&s);
		return *s == 0 ? 0 : -1;
	}

	// Numeric comparison patterns: $N OP INT, NR OP INT, NF OP INT
	if (*s == '$' || awk_starts_with_kw(s, "NR") || awk_starts_with_kw(s, "NF")) {
		const char *save = s;
		if (awk_parse_numeric_pattern(out, &s) == 0) {
			awk_skip_spaces(&s);
			if (*s == 0) {
				out->has_action = 0;
				return 0;
			}
			if (*s != '{') return -1;
			s++;
			if (awk_parse_action(out, &s, 1) != 0) return -1;
			awk_skip_spaces(&s);
			return *s == 0 ? 0 : -1;
		}
		// Not a valid numeric pattern; restore and continue parsing as action.
		s = save;
	}

	if (*s == '{') {
		s++;
		if (awk_parse_action(out, &s, 1) != 0) return -1;
		awk_skip_spaces(&s);
		return *s == 0 ? 0 : -1;
	}

	// Action without braces: print ...
	if (awk_parse_action(out, &s, 0) != 0) return -1;
	awk_skip_spaces(&s);
	return *s == 0 ? 0 : -1;
}

static mc_i64 awk_parse_i64_slice(const char *s, mc_u32 len, int *ok) {
	// Trim ASCII spaces/tabs.
	*ok = 0;
	mc_u32 a = 0;
	while (a < len && (s[a] == ' ' || s[a] == '\t')) a++;
	mc_u32 b = len;
	while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) b--;
	if (a >= b) return 0;

	int neg = 0;
	if (s[a] == '+' || s[a] == '-') {
		neg = (s[a] == '-');
		a++;
	}
	if (a >= b) return 0;
	if (s[a] < '0' || s[a] > '9') return 0;

	mc_u64 v = 0;
	while (a < b && s[a] >= '0' && s[a] <= '9') {
		v = v * 10u + (mc_u64)(s[a] - '0');
		a++;
	}
	*ok = 1;
	return neg ? -(mc_i64)v : (mc_i64)v;
}

static int awk_eval_numeric_pattern(const struct awk_prog *p, const char *line, mc_u32 len, mc_u64 nr, mc_u32 nf, const mc_u32 *starts, const mc_u32 *ends) {
	mc_i64 lhs = 0;
	int ok = 1;
	if (p->pat_lhs_kind == 2) {
		lhs = (mc_i64)nr;
	} else if (p->pat_lhs_kind == 3) {
		lhs = (mc_i64)nf;
	} else if (p->pat_lhs_kind == 1) {
		mc_u32 idx = p->pat_field_index;
		if (idx == 0) {
			lhs = awk_parse_i64_slice(line, len, &ok);
		} else {
			mc_u32 f = idx - 1;
			if (f < nf) {
				mc_u32 a = starts[f];
				mc_u32 b = ends[f];
				if (a <= b && b <= len) lhs = awk_parse_i64_slice(line + a, b - a, &ok);
				else ok = 0;
			} else {
				ok = 0;
			}
		}
	} else {
		ok = 0;
	}
	if (!ok) return 0;

	mc_i64 rhs = p->pat_rhs;
	switch (p->pat_op) {
		case 1: return lhs == rhs;
		case 2: return lhs != rhs;
		case 3: return lhs < rhs;
		case 4: return lhs <= rhs;
		case 5: return lhs > rhs;
		case 6: return lhs >= rhs;
		default: return 0;
	}
}

// --- Field splitting

static mc_u32 awk_split_fields_whitespace(char *line, mc_u32 len, mc_u32 *starts, mc_u32 *ends, mc_u32 max_fields) {
	mc_u32 nf = 0;
	mc_u32 i = 0;
	while (i < len) {
		while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
		if (i >= len) break;
		if (nf >= max_fields) break;
		starts[nf] = i;
		while (i < len && line[i] != ' ' && line[i] != '\t') i++;
		ends[nf] = i;
		nf++;
	}
	return nf;
}

static mc_u32 awk_split_fields_delim(char *line, mc_u32 len, char delim, mc_u32 *starts, mc_u32 *ends, mc_u32 max_fields) {
	mc_u32 nf = 0;
	mc_u32 i = 0;
	// awk with single-char FS: empty fields are allowed.
	if (nf < max_fields) {
		starts[nf] = 0;
	}
	for (i = 0; i <= len; i++) {
		if (i == len || line[i] == delim) {
			if (nf >= max_fields) break;
			ends[nf] = i;
			nf++;
			if (i != len) {
				if (nf < max_fields) starts[nf] = i + 1;
			}
		}
	}
	return nf;
}

// --- Execution

static int awk_write_u64(mc_u64 v) {
	mc_i64 w = mc_write_u64_dec(1, v);
	return (w < 0) ? -1 : 0;
}

static int awk_print_line(const struct awk_prog *p, char *line, mc_u32 len, mc_u64 nr, char fs_mode, char fs_delim, int *any_fail) {
	(void)any_fail;
	// trim trailing newline for field parsing/printing; keep original newline behavior by printing our own newline.
	if (len > 0 && line[len - 1] == '\n') len--;

	mc_u32 starts[512];
	mc_u32 ends[512];
	mc_u32 nf = 0;
	if (fs_mode == 0) nf = awk_split_fields_whitespace(line, len, starts, ends, 512);
	else nf = awk_split_fields_delim(line, len, fs_delim, starts, ends, 512);

	// Determine whether to run action based on pattern.
	if (p->has_pattern) {
		if (p->pattern_kind == 1) {
			// Build NUL-terminated view for regex matcher.
			char tmp[65536];
			if (len >= (mc_u32)sizeof(tmp)) {
				(void)mc_write_str(2, "awk: line too long\n");
				return -1;
			}
			for (mc_u32 i = 0; i < len; i++) tmp[i] = line[i];
			tmp[len] = 0;
			if (!awk_match(p->pattern, tmp)) return 0;
		} else if (p->pattern_kind == 2) {
			if (!awk_eval_numeric_pattern(p, line, len, nr, nf, starts, ends)) return 0;
		} else {
			return 0;
		}
	}

	// Default action for pattern-only programs is print $0
	if (!p->has_action) {
		if (mc_write_all(1, line, len) < 0) return -1;
		if (mc_write_all(1, "\n", 1) < 0) return -1;
		return 0;
	}

	// Print action.
	if (p->n_items == 0) {
		// plain print
		if (mc_write_all(1, line, len) < 0) return -1;
		if (mc_write_all(1, "\n", 1) < 0) return -1;
		return 0;
	}

	for (mc_u32 i = 0; i < p->n_items; i++) {
		if (i != 0) {
			if (mc_write_all(1, " ", 1) < 0) return -1;
		}
		const struct awk_item *it = &p->items[i];
		if (it->kind == AWK_ITEM_FIELD) {
			mc_u32 idx = it->field_index;
			if (idx == 0) {
				if (mc_write_all(1, line, len) < 0) return -1;
			} else {
				// fields are 1-based
				mc_u32 f = idx - 1;
				if (f < nf) {
					mc_u32 a = starts[f];
					mc_u32 b = ends[f];
					if (a <= b && b <= len) {
						if (mc_write_all(1, line + a, (mc_usize)(b - a)) < 0) return -1;
					}
				}
			}
			continue;
		}
		if (it->kind == AWK_ITEM_NR) {
			if (awk_write_u64(nr) != 0) return -1;
			continue;
		}
		if (it->kind == AWK_ITEM_NF) {
			if (awk_write_u64((mc_u64)nf) != 0) return -1;
			continue;
		}
		if (it->kind == AWK_ITEM_STR) {
			if (it->str_off + it->str_len <= (mc_u32)sizeof(p->str_pool)) {
				if (mc_write_all(1, p->str_pool + it->str_off, it->str_len) < 0) return -1;
			}
			continue;
		}
	}
	if (mc_write_all(1, "\n", 1) < 0) return -1;
	return 0;
}

static int awk_process_fd(const char *argv0, const struct awk_prog *p, mc_i32 fd, char fs_mode, char fs_delim, mc_u64 *io_nr, int *any_fail) {
	char rbuf[32768];
	mc_usize rpos = 0;
	mc_usize rlen = 0;
	char line[65536];
	mc_u32 llen = 0;

	for (;;) {
		if (rpos == rlen) {
			mc_i64 r = mc_sys_read(fd, rbuf, sizeof(rbuf));
			if (r < 0) {
				mc_print_errno(argv0, "read", r);
				*any_fail = 1;
				return -1;
			}
			if (r == 0) break;
			rpos = 0;
			rlen = (mc_usize)r;
		}
		char c = rbuf[rpos++];
		if (llen + 1 >= (mc_u32)sizeof(line)) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": line too long\n");
			*any_fail = 1;
			return -1;
		}
		line[llen++] = c;
		if (c == '\n') {
			*io_nr = *io_nr + 1;
			if (awk_print_line(p, line, llen, *io_nr, fs_mode, fs_delim, any_fail) != 0) {
				*any_fail = 1;
				return -1;
			}
			llen = 0;
		}
	}
	if (llen > 0) {
		*io_nr = *io_nr + 1;
		if (awk_print_line(p, line, llen, *io_nr, fs_mode, fs_delim, any_fail) != 0) {
			*any_fail = 1;
			return -1;
		}
	}
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "awk";

	char fs_mode = 0; // 0 whitespace, 1 single-byte delimiter
	char fs_delim = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-') break;
		if (mc_streq(a, "-F")) {
			i++;
			if (i >= argc || !argv[i]) mc_die_usage(argv0, "awk [-F FS] [--] PROGRAM [FILE...]");
			const char *fs = argv[i];
			mc_usize n = mc_strlen(fs);
			if (n != 1) mc_die_usage(argv0, "awk: only single-byte -F delimiters supported");
			fs_mode = 1;
			fs_delim = fs[0];
			continue;
		}
		mc_die_usage(argv0, "awk [-F FS] [--] PROGRAM [FILE...]");
	}

	if (i >= argc || !argv[i]) mc_die_usage(argv0, "awk [-F FS] [--] PROGRAM [FILE...]");
	const char *program = argv[i++];

	struct awk_prog prog;
	if (awk_parse_program(program, &prog) != 0) {
		mc_die_usage(argv0, "awk: unsupported PROGRAM (supported: /re/ {print...}, {print...}, or print...)");
	}

	int any_fail = 0;
	mc_u64 nr = 0;
	if (i >= argc) {
		(void)awk_process_fd(argv0, &prog, 0, fs_mode, fs_delim, &nr, &any_fail);
		return any_fail ? 1 : 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) continue;
		if (mc_streq(path, "-")) {
			(void)awk_process_fd(argv0, &prog, 0, fs_mode, fs_delim, &nr, &any_fail);
			continue;
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) {
			mc_print_errno(argv0, path, fd);
			any_fail = 1;
			continue;
		}
		(void)awk_process_fd(argv0, &prog, (mc_i32)fd, fs_mode, fs_delim, &nr, &any_fail);
		(void)mc_sys_close((mc_i32)fd);
	}

	return any_fail ? 1 : 0;
}
