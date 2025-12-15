#include "mc.h"

// Minimal-ish sed subset:
// - Commands:
//   - s/REGEX/REPL/[g][p]
//   - d, p
//   - h, H, g, G, x (hold space)
// - Addressing:
//   - Ncmd, $cmd, /REGEX/cmd
//   - Ranges: addr1,addr2cmd
// - Regex: shared tiny BRE-ish subset (see mc_regex_* in src/sb.[ch])
//   - Capture groups: \( ... \) and backrefs \1..\9 in replacement.
// - Options: -n (suppress default printing), -e SCRIPT (repeatable), -- end of options.
// - Input: FILE... or stdin.

#define SED_MAX_CMDS 16
static mc_usize sed_cstr_len(const char *s) {
	return mc_strlen(s);
}

static void sed_memcpy(char *dst, const char *src, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) dst[i] = src[i];
}

static int sed_streq(const char *a, const char *b) {
	return mc_streq(a, b);
}

// --- Parsing s/// command

struct sed_subst {
	char regex[512];
	char repl[512];
	int global;
	int print_on_subst;
};

enum sed_addr_kind {
	SED_ADDR_NONE = 0,
	SED_ADDR_LINE,
	SED_ADDR_LAST,
	SED_ADDR_REGEX,
};

struct sed_addr {
	enum sed_addr_kind kind;
	mc_u64 line;
	char regex[512];
};

enum sed_cmd_kind {
	SED_CMD_SUBST = 0,
	SED_CMD_DEL,
	SED_CMD_PRINT,
	SED_CMD_H,
	SED_CMD_HAPPEND,
	SED_CMD_G,
	SED_CMD_GAPPEND,
	SED_CMD_X,
};

struct sed_cmd {
	enum sed_cmd_kind kind;
	struct sed_addr addr1;
	struct sed_addr addr2;
	int has_range;
	int range_active;
	struct sed_subst subst;
};

static int sed_parse_until_delim(const char *s, char delim, char *out, mc_usize out_sz, const char **out_next) {
	mc_usize o = 0;
	const char *p = s;
	while (*p) {
		char c = *p;
		if (c == delim) {
			out[o] = 0;
			*out_next = p + 1;
			return 0;
		}
		if (c == '\\' && p[1] != 0) {
			// Keep escapes as-is; matcher/repl emitter interpret them.
			if (o + 2 >= out_sz) return -1;
			out[o++] = *p++;
			out[o++] = *p++;
			continue;
		}
		if (o + 1 >= out_sz) return -1;
		out[o++] = c;
		p++;
	}
	return -1;
}


static int sed_parse_subst(const char *script, struct sed_subst *out) {
	if (!script || !*script || !out) return -1;
	if (script[0] != 's') return -1;
	char delim = script[1];
	if (delim == 0) return -1;

	const char *p = script + 2;
	const char *next = 0;
	if (sed_parse_until_delim(p, delim, out->regex, sizeof(out->regex), &next) != 0) return -1;
	if (out->regex[0] == 0) return -1;
	p = next;
	if (sed_parse_until_delim(p, delim, out->repl, sizeof(out->repl), &next) != 0) return -1;
	p = next;

	out->global = 0;
	out->print_on_subst = 0;
	for (; *p; p++) {
		if (*p == 'g') {
			out->global = 1;
			continue;
		}
		if (*p == 'p') {
			out->print_on_subst = 1;
			continue;
		}
		return -1;
	}
	return 0;
}

static int sed_parse_addr(const char *s, struct sed_addr *out, const char **out_next) {
	if (!out || !out_next) return -1;
	out->kind = SED_ADDR_NONE;
	out->line = 0;
	out->regex[0] = 0;
	*out_next = s;
	if (!s || !*s) return 0;

	if (*s == '$') {
		out->kind = SED_ADDR_LAST;
		*out_next = s + 1;
		return 0;
	}

	if (*s == '/') {
		// /REGEX/
		const char *p = s + 1;
		const char *next = 0;
		if (sed_parse_until_delim(p, '/', out->regex, sizeof(out->regex), &next) != 0) return -1;
		out->kind = SED_ADDR_REGEX;
		*out_next = next;
		// Validate now so we can treat it as a usage error.
		const char *ms = 0;
		const char *me = 0;
		if (mc_regex_match_first(out->regex, "", 0u, &ms, &me, 0) < 0) return -1;
		return 0;
	}

	// Line number
	mc_u64 v = 0;
	const char *p = s;
	if (mc_parse_u64_dec_prefix(&p, &v) != 0) return 0;
	out->kind = SED_ADDR_LINE;
	out->line = v;
	*out_next = p;
	return 0;
}

static int sed_parse_cmd(const char *script, struct sed_cmd *out) {
	if (!script || !*script || !out) return -1;

	const char *p = 0;
	if (sed_parse_addr(script, &out->addr1, &p) != 0) return -1;
	out->addr2.kind = SED_ADDR_NONE;
	out->addr2.line = 0;
	out->addr2.regex[0] = 0;
	out->has_range = 0;
	out->range_active = 0;

	if (!p || !*p) return -1;
	if (*p == ',') {
		out->has_range = 1;
		p++;
		if (sed_parse_addr(p, &out->addr2, &p) != 0) return -1;
		if (!p || !*p) return -1;
	}

	if (*p == 'd' && p[1] == 0) {
		out->kind = SED_CMD_DEL;
		return 0;
	}
	if (*p == 'p' && p[1] == 0) {
		out->kind = SED_CMD_PRINT;
		return 0;
	}
	if (*p == 'h' && p[1] == 0) {
		out->kind = SED_CMD_H;
		return 0;
	}
	if (*p == 'H' && p[1] == 0) {
		out->kind = SED_CMD_HAPPEND;
		return 0;
	}
	if (*p == 'g' && p[1] == 0) {
		out->kind = SED_CMD_G;
		return 0;
	}
	if (*p == 'G' && p[1] == 0) {
		out->kind = SED_CMD_GAPPEND;
		return 0;
	}
	if (*p == 'x' && p[1] == 0) {
		out->kind = SED_CMD_X;
		return 0;
	}
	if (*p == 's') {
		out->kind = SED_CMD_SUBST;
		if (sed_parse_subst(p, &out->subst) != 0) return -1;
		// Validate regex now.
		const char *ms = 0;
		const char *me = 0;
		if (mc_regex_match_first(out->subst.regex, "", 0u, &ms, &me, 0) < 0) return -1;
		return 0;
	}
	return -1;
}

static int sed_emit_repl(char *dst, mc_usize dst_sz, mc_usize *ioff, const char *repl, const char *mstart, const char *mend, const struct mc_regex_caps *caps) {
	// Expand:
	// - & => whole match
	// - \1..\9 => capture group
	// - \X => literal X (including \&)
	// - \n => newline
	const char *p = repl;
	while (*p) {
		char c = *p++;
		if (c == '&') {
			mc_usize n = (mc_usize)(mend - mstart);
			if (*ioff + n >= dst_sz) return -1;
			sed_memcpy(dst + *ioff, mstart, n);
			*ioff += n;
			continue;
		}
		if (c == '\\' && *p) {
			char e = *p++;
			if (e >= '1' && e <= '9') {
				mc_u32 idx = (mc_u32)(e - '0');
				if (caps && idx <= caps->n && caps->start[idx] && caps->end[idx] && caps->end[idx] >= caps->start[idx]) {
					mc_usize n = (mc_usize)(caps->end[idx] - caps->start[idx]);
					if (*ioff + n >= dst_sz) return -1;
					sed_memcpy(dst + *ioff, caps->start[idx], n);
					*ioff += n;
				}
				continue;
			}
			if (e == 'n') {
				e = '\n';
			}
			if (*ioff + 1 >= dst_sz) return -1;
			dst[(*ioff)++] = e;
			continue;
		}
		if (*ioff + 1 >= dst_sz) return -1;
		dst[(*ioff)++] = c;
	}
	return 0;
}

static int sed_apply_subst(const struct sed_subst *sc, const char *in, char *out, mc_usize out_sz, int *did_subst) {
	*did_subst = 0;
	// in is a NUL-terminated line without trailing newline.
	const char *pos = in;
	char *w = out;
	mc_usize woff = 0;

	for (;;) {
		const char *mstart = 0;
		const char *mend = 0;
		struct mc_regex_caps caps;
		int mr = mc_regex_match_first(sc->regex, pos, 0u, &mstart, &mend, &caps);
		if (mr < 0) {
			return -1;
		}
		if (mr == 0) {
			// Copy remainder.
			mc_usize n = sed_cstr_len(pos);
			if (woff + n + 1 > out_sz) return -1;
			sed_memcpy(w + woff, pos, n);
			woff += n;
			break;
		}

		*did_subst = 1;

		// Copy prefix [pos, mstart)
		mc_usize pre = (mc_usize)(mstart - pos);
		if (woff + pre + 1 > out_sz) return -1;
		sed_memcpy(w + woff, pos, pre);
		woff += pre;

		// Emit replacement.
		if (sed_emit_repl(w, out_sz, &woff, sc->repl, mstart, mend, &caps) != 0) return -1;

		// Advance.
		pos = mend;

		if (!sc->global) {
			// Copy remainder.
			mc_usize n = sed_cstr_len(pos);
			if (woff + n + 1 > out_sz) return -1;
			sed_memcpy(w + woff, pos, n);
			woff += n;
			break;
		}

		// Avoid infinite loops on empty matches.
		if (mend == mstart) {
			if (*pos == 0) break;
			if (woff + 1 + 1 > out_sz) return -1;
			w[woff++] = *pos;
			pos++;
		}
	}

	w[woff] = 0;
	return 0;
}

static int sed_addr_matches(const struct sed_addr *a, mc_u64 lineno, int is_last, const char *pat) {
	if (!a) return 0;
	if (a->kind == SED_ADDR_NONE) return 1;
	if (a->kind == SED_ADDR_LINE) return lineno == a->line;
	if (a->kind == SED_ADDR_LAST) return is_last;
	if (a->kind == SED_ADDR_REGEX) {
		const char *ms = 0;
		const char *me = 0;
		int r = mc_regex_match_first(a->regex, pat ? pat : "", 0u, &ms, &me, 0);
		if (r < 0) return 0;
		return r;
	}
	return 0;
}

static int sed_cmd_is_active(struct sed_cmd *cmd, mc_u64 lineno, int is_last, const char *pat) {
	if (!cmd) return 0;
	if (!cmd->has_range) {
		return sed_addr_matches(&cmd->addr1, lineno, is_last, pat);
	}
	int start_match = sed_addr_matches(&cmd->addr1, lineno, is_last, pat);
	int end_match = sed_addr_matches(&cmd->addr2, lineno, is_last, pat);
	int active_for_line = cmd->range_active || start_match;
	int next_active = cmd->range_active;
	if (!cmd->range_active && start_match) next_active = 1;
	if (active_for_line && end_match) next_active = 0;
	cmd->range_active = next_active;
	return active_for_line;
}

static int sed_print_line(const char *argv0, const char *s, int has_nl) {
	mc_i64 w = mc_write_str(1, s);
	if (w < 0) mc_die_errno(argv0, "write", w);
	if (has_nl) {
		w = mc_write_all(1, "\n", 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}
	return 0;
}

static int sed_process_line(const char *argv0, struct sed_cmd *cmds, mc_u32 ncmds, int suppress_default, char *hold, mc_usize hold_sz, mc_usize *io_hold_len, const char *line, mc_usize len, mc_u64 lineno, int is_last, int *any_fail) {
	(void)any_fail;
	// Separate trailing newline (if present).
	int has_nl = 0;
	if (len > 0 && line[len - 1] == '\n') {
		has_nl = 1;
		len--;
	}

	// Copy into a NUL-terminated buffer.
	char pat[65536];
	if (len >= sizeof(pat)) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": line too long\n");
		return -1;
	}
	for (mc_usize i = 0; i < len; i++) pat[i] = line[i];
	pat[len] = 0;

	char tmp[262144];
	int deleted = 0;
	int printed = 0;

	for (mc_u32 ci = 0; ci < ncmds; ci++) {
		struct sed_cmd *cmd = &cmds[ci];
		if (!sed_cmd_is_active(cmd, lineno, is_last, pat)) {
			continue;
		}
		if (cmd->kind == SED_CMD_DEL) {
			deleted = 1;
			break;
		}
		if (cmd->kind == SED_CMD_PRINT) {
			printed = 1;
			(void)sed_print_line(argv0, pat, has_nl);
			continue;
		}
		if (cmd->kind == SED_CMD_H) {
			mc_usize plen = sed_cstr_len(pat);
			if (plen + 1 > hold_sz) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": hold space too long\n");
				return -1;
			}
			for (mc_usize k = 0; k <= plen; k++) hold[k] = pat[k];
			*io_hold_len = plen;
			continue;
		}
		if (cmd->kind == SED_CMD_HAPPEND) {
			mc_usize plen = sed_cstr_len(pat);
			mc_usize hlen = *io_hold_len;
			if (hlen + 1 + plen + 1 > hold_sz) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": hold space too long\n");
				return -1;
			}
			hold[hlen++] = '\n';
			for (mc_usize k = 0; k < plen; k++) hold[hlen + k] = pat[k];
			hlen += plen;
			hold[hlen] = 0;
			*io_hold_len = hlen;
			continue;
		}
		if (cmd->kind == SED_CMD_G) {
			mc_usize hlen = *io_hold_len;
			if (hlen + 1 > sizeof(pat)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": pattern space too long\n");
				return -1;
			}
			for (mc_usize k = 0; k <= hlen; k++) pat[k] = hold[k];
			continue;
		}
		if (cmd->kind == SED_CMD_GAPPEND) {
			mc_usize plen = sed_cstr_len(pat);
			mc_usize hlen = *io_hold_len;
			if (plen + 1 + hlen + 1 > sizeof(pat)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": pattern space too long\n");
				return -1;
			}
			pat[plen++] = '\n';
			for (mc_usize k = 0; k < hlen; k++) pat[plen + k] = hold[k];
			plen += hlen;
			pat[plen] = 0;
			continue;
		}
		if (cmd->kind == SED_CMD_X) {
			mc_usize plen = sed_cstr_len(pat);
			mc_usize hlen = *io_hold_len;
			if (plen + 1 > sizeof(tmp) || hlen + 1 > sizeof(pat) || plen + 1 > hold_sz) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": swap too long\n");
				return -1;
			}
			// tmp <- pat
			for (mc_usize k = 0; k <= plen; k++) tmp[k] = pat[k];
			// pat <- hold
			for (mc_usize k = 0; k <= hlen; k++) pat[k] = hold[k];
			// hold <- tmp
			for (mc_usize k = 0; k <= plen; k++) hold[k] = tmp[k];
			*io_hold_len = plen;
			continue;
		}
		if (cmd->kind == SED_CMD_SUBST) {
			int did = 0;
			if (sed_apply_subst(&cmd->subst, pat, tmp, sizeof(tmp), &did) != 0) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": output too long\n");
				return -1;
			}
			// Update pattern space.
			mc_usize tlen = sed_cstr_len(tmp);
			if (tlen >= sizeof(pat)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": output too long\n");
				return -1;
			}
			for (mc_usize k = 0; k <= tlen; k++) pat[k] = tmp[k];

			if (did && cmd->subst.print_on_subst) {
				printed = 1;
				(void)sed_print_line(argv0, pat, has_nl);
			}
			continue;
		}
	}

	if (!deleted && !suppress_default && !printed) {
		(void)sed_print_line(argv0, pat, has_nl);
	}

	return 0;
}

static int sed_process_fd(const char *argv0, struct sed_cmd *cmds, mc_u32 ncmds, int suppress_default, char *hold, mc_usize hold_sz, mc_usize *io_hold_len, mc_i32 fd, int *any_fail) {
	char rbuf[32768];
	mc_usize rpos = 0;
	mc_usize rlen = 0;

	char linebuf[65536];
	mc_usize llen = 0;

	char prev[65536];
	mc_usize prev_len = 0;
	int have_prev = 0;
	mc_u64 lineno = 0;

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
		if (llen + 1 >= sizeof(linebuf)) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": line too long\n");
			*any_fail = 1;
			return -1;
		}
		linebuf[llen++] = c;
		if (c == '\n') {
			if (have_prev) {
				lineno++;
				if (sed_process_line(argv0, cmds, ncmds, suppress_default, hold, hold_sz, io_hold_len, prev, prev_len, lineno, 0, any_fail) != 0) {
					*any_fail = 1;
					return -1;
				}
			}
			// move current to prev
			if (llen >= sizeof(prev)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": line too long\n");
				*any_fail = 1;
				return -1;
			}
			for (mc_usize i = 0; i < llen; i++) prev[i] = linebuf[i];
			prev_len = llen;
			have_prev = 1;
			llen = 0;
		}
	}

	// If there's a final partial line (no newline), make it prev and process it as last.
	if (llen > 0) {
		if (have_prev) {
			lineno++;
			if (sed_process_line(argv0, cmds, ncmds, suppress_default, hold, hold_sz, io_hold_len, prev, prev_len, lineno, 0, any_fail) != 0) {
				*any_fail = 1;
				return -1;
			}
		}
		for (mc_usize i = 0; i < llen; i++) prev[i] = linebuf[i];
		prev_len = llen;
		have_prev = 1;
		llen = 0;
	}

	if (have_prev) {
		lineno++;
		if (sed_process_line(argv0, cmds, ncmds, suppress_default, hold, hold_sz, io_hold_len, prev, prev_len, lineno, 1, any_fail) != 0) {
			*any_fail = 1;
			return -1;
		}
	}

	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "sed";

	int suppress_default = 0; // -n
	struct sed_cmd cmds[SED_MAX_CMDS];
	mc_u32 ncmds = 0;

	char hold[65536];
	mc_usize hold_len = 0;
	hold[0] = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (sed_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-') break;
		if (sed_streq(a, "-n")) {
			suppress_default = 1;
			continue;
		}
		if (sed_streq(a, "-e")) {
			i++;
			if (i >= argc || !argv[i]) mc_die_usage(argv0, "sed [-n] [-e SCRIPT] [SCRIPT] [FILE...]");
			if (ncmds >= SED_MAX_CMDS) mc_die_usage(argv0, "sed [-n] [-e SCRIPT] [SCRIPT] [FILE...]");
			if (sed_parse_cmd(argv[i], &cmds[ncmds]) != 0) {
				mc_die_usage(argv0, "sed [-n] [-e SCRIPT] [SCRIPT] [FILE...] (invalid SCRIPT)");
			}
			ncmds++;
			continue;
		}
		// Unknown option.
		mc_die_usage(argv0, "sed [-n] [-e SCRIPT] [SCRIPT] [FILE...]");
	}

	if (ncmds == 0) {
		if (i >= argc || !argv[i]) {
			mc_die_usage(argv0, "sed [-n] [-e SCRIPT] [SCRIPT] [FILE...]");
		}
		if (sed_parse_cmd(argv[i], &cmds[ncmds]) != 0) {
			mc_die_usage(argv0, "sed [-n] [-e SCRIPT] [SCRIPT] [FILE...] (invalid SCRIPT)");
		}
		ncmds++;
		i++;
	}

	int any_fail = 0;
	if (i >= argc) {
		// stdin
		(void)sed_process_fd(argv0, cmds, ncmds, suppress_default, hold, sizeof(hold), &hold_len, 0, &any_fail);
		return any_fail ? 1 : 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) continue;
		if (sed_streq(path, "-")) {
			(void)sed_process_fd(argv0, cmds, ncmds, suppress_default, hold, sizeof(hold), &hold_len, 0, &any_fail);
			continue;
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) {
			mc_print_errno(argv0, path, fd);
			any_fail = 1;
			continue;
		}
		(void)sed_process_fd(argv0, cmds, ncmds, suppress_default, hold, sizeof(hold), &hold_len, (mc_i32)fd, &any_fail);
		(void)mc_sys_close((mc_i32)fd);
	}

	return any_fail ? 1 : 0;
}
