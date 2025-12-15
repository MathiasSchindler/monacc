#include "mc.h"

// Tiny regex matcher (BRE-ish subset) used by grep/sed.

enum mc_re_atom_kind {
	MC_RE_ATOM_LITERAL = 0,
	MC_RE_ATOM_DOT,
	MC_RE_ATOM_CLASS,
	MC_RE_ATOM_GROUP_START,
	MC_RE_ATOM_GROUP_END,
};

static int mc_re_is_group_start(const char *re) {
	return re && re[0] == '\\' && re[1] == '(';
}

static int mc_re_is_group_end(const char *re) {
	return re && re[0] == '\\' && re[1] == ')';
}

static int mc_re_parse_class_len(const char *re) {
	const char *p = re + 1;
	if (*p == 0) return -1;
	if (*p == ']') p++;
	for (; *p; p++) {
		if (*p == '\\' && p[1] != 0) {
			p++;
			continue;
		}
		if (*p == ']') {
			return (int)((p - re) + 1);
		}
	}
	return -1;
}

static int mc_re_atom_len_and_kind(const char *re, enum mc_re_atom_kind *out_kind) {
	if (!re || !*re) return 0;
	if (re[0] == '\\' && re[1] != 0) {
		if (re[1] == '(') {
			*out_kind = MC_RE_ATOM_GROUP_START;
			return 2;
		}
		if (re[1] == ')') {
			*out_kind = MC_RE_ATOM_GROUP_END;
			return 2;
		}
		*out_kind = MC_RE_ATOM_LITERAL;
		return 2;
	}
	if (re[0] == '.') {
		*out_kind = MC_RE_ATOM_DOT;
		return 1;
	}
	if (re[0] == '[') {
		int n = mc_re_parse_class_len(re);
		if (n < 0) return -1;
		*out_kind = MC_RE_ATOM_CLASS;
		return n;
	}
	*out_kind = MC_RE_ATOM_LITERAL;
	return 1;
}

static mc_u8 mc_re_fold(mc_u8 c, mc_u32 flags) {
	if (flags & MC_REGEX_ICASE) return mc_tolower_ascii(c);
	return c;
}

static int mc_re_class_matches(const char *cls, int len, mc_u8 ch, mc_u32 flags, int *out_invalid) {
	*out_invalid = 0;
	if (!cls || len < 2 || cls[0] != '[' || cls[len - 1] != ']') {
		*out_invalid = 1;
		return 0;
	}
	const char *p = cls + 1;
	const char *end = cls + len - 1;
	int neg = 0;
	if (p < end && *p == '^') {
		neg = 1;
		p++;
	}
	int matched = 0;
	mc_u8 cch = mc_re_fold(ch, flags);
	if (p < end && *p == ']') {
		matched = (cch == mc_re_fold((mc_u8)']', flags));
		p++;
	}

	while (p < end) {
		mc_u8 a;
		if (*p == '\\' && (p + 1) < end) {
			a = (mc_u8)p[1];
			p += 2;
		} else {
			a = (mc_u8)(*p++);
		}
		a = mc_re_fold(a, flags);

		if (p < end && *p == '-' && (p + 1) < end && p[1] != ']') {
			p++;
			mc_u8 b;
			if (*p == '\\' && (p + 1) < end) {
				b = (mc_u8)p[1];
				p += 2;
			} else {
				b = (mc_u8)(*p++);
			}
			b = mc_re_fold(b, flags);
			mc_u8 lo = a < b ? a : b;
			mc_u8 hi = a < b ? b : a;
			if (cch >= lo && cch <= hi) matched = 1;
			continue;
		}

		if (cch == a) matched = 1;
	}

	return neg ? !matched : matched;
}

static int mc_re_atom_matches(const char *atom, int atom_len, enum mc_re_atom_kind kind, mc_u8 ch, mc_u32 flags, int *out_invalid) {
	*out_invalid = 0;
	if (kind == MC_RE_ATOM_DOT) return ch != 0;
	if (kind == MC_RE_ATOM_CLASS) return mc_re_class_matches(atom, atom_len, ch, flags, out_invalid);
	if (kind == MC_RE_ATOM_LITERAL) {
		mc_u8 a;
		if (atom_len == 2 && atom[0] == '\\') a = (mc_u8)atom[1];
		else a = (mc_u8)atom[0];
		return mc_re_fold(ch, flags) == mc_re_fold(a, flags);
	}
	*out_invalid = 1;
	return 0;
}

static int mc_re_match_here(const char *re, const char *text, mc_u32 flags, int stop_on_group_end,
	const char **out_re, const char **out_text, struct mc_regex_caps *caps, mc_u32 nextcap, mc_u32 *out_nextcap);

static int mc_re_match_star(const char *atom, int atom_len, enum mc_re_atom_kind kind, const char *re_rest, const char *text, mc_u32 flags,
	int stop_on_group_end, const char **out_re, const char **out_text, struct mc_regex_caps *caps, mc_u32 nextcap, mc_u32 *out_nextcap) {
	const char *t = text;
	while (*t) {
		int inv = 0;
		if (!mc_re_atom_matches(atom, atom_len, kind, (mc_u8)*t, flags, &inv)) {
			if (inv) return -1;
			break;
		}
		t++;
	}
	for (;;) {
		struct mc_regex_caps caps_snap = *caps;
		mc_u32 nc_snap = nextcap;
		int r = mc_re_match_here(re_rest, t, flags, stop_on_group_end, out_re, out_text, &caps_snap, nc_snap, &nc_snap);
		if (r == 1) {
			*caps = caps_snap;
			*out_nextcap = nc_snap;
			return 1;
		}
		if (r < 0) return r;
		if (t == text) break;
		t--;
	}
	return 0;
}

static int mc_re_match_here(const char *re, const char *text, mc_u32 flags, int stop_on_group_end,
	const char **out_re, const char **out_text, struct mc_regex_caps *caps, mc_u32 nextcap, mc_u32 *out_nextcap) {
	if (!re || !text || !out_re || !out_text || !caps || !out_nextcap) return -1;

	if (stop_on_group_end) {
		if (*re == 0) return -1;
		if (mc_re_is_group_end(re)) {
			*out_re = re;
			*out_text = text;
			*out_nextcap = nextcap;
			return 1;
		}
	} else {
		if (mc_re_is_group_end(re)) return -1;
	}

	if (*re == 0) {
		*out_re = re;
		*out_text = text;
		*out_nextcap = nextcap;
		return 1;
	}

	if (!stop_on_group_end && re[0] == '$' && re[1] == 0) {
		if (*text == 0) {
			*out_re = re + 1;
			*out_text = text;
			*out_nextcap = nextcap;
			return 1;
		}
		return 0;
	}

	if (mc_re_is_group_start(re)) {
		if (nextcap >= MC_REGEX_MAX_CAPS) return -1;
		mc_u32 cap_id = nextcap + 1;
		struct mc_regex_caps caps_snap = *caps;
		caps_snap.start[cap_id] = text;

		const char *inner_re = 0;
		const char *inner_text = 0;
		mc_u32 nc_after = cap_id;
		int r = mc_re_match_here(re + 2, text, flags, 1, &inner_re, &inner_text, &caps_snap, cap_id, &nc_after);
		if (r != 1) return r;
		if (!mc_re_is_group_end(inner_re)) return -1;
		caps_snap.end[cap_id] = inner_text;
		if (caps_snap.n < cap_id) caps_snap.n = cap_id;

		const char *after_re = 0;
		const char *after_text = 0;
		mc_u32 nc_final = nc_after;
		r = mc_re_match_here(inner_re + 2, inner_text, flags, stop_on_group_end, &after_re, &after_text, &caps_snap, nc_final, &nc_final);
		if (r == 1) {
			*caps = caps_snap;
			*out_re = after_re;
			*out_text = after_text;
			*out_nextcap = nc_final;
		}
		return r;
	}

	enum mc_re_atom_kind kind;
	int atom_len = mc_re_atom_len_and_kind(re, &kind);
	if (atom_len < 0) return -1;
	if (atom_len == 0) {
		*out_re = re;
		*out_text = text;
		*out_nextcap = nextcap;
		return 1;
	}
	if (kind == MC_RE_ATOM_GROUP_END) return stop_on_group_end ? 1 : -1;
	if (kind == MC_RE_ATOM_GROUP_START) return -1;

	if (re[atom_len] == '*') {
		return mc_re_match_star(re, atom_len, kind, re + atom_len + 1, text, flags, stop_on_group_end, out_re, out_text, caps, nextcap, out_nextcap);
	}

	if (*text) {
		int inv = 0;
		if (mc_re_atom_matches(re, atom_len, kind, (mc_u8)*text, flags, &inv)) {
			return mc_re_match_here(re + atom_len, text + 1, flags, stop_on_group_end, out_re, out_text, caps, nextcap, out_nextcap);
		}
		if (inv) return -1;
	}
	return 0;
}

int mc_regex_match_first(const char *re, const char *text, mc_u32 flags, const char **out_start, const char **out_end, struct mc_regex_caps *out_caps) {
	if (!re || !text || !out_start || !out_end) return -1;

	struct mc_regex_caps caps;
	for (mc_u32 i = 0; i <= MC_REGEX_MAX_CAPS; i++) {
		caps.start[i] = 0;
		caps.end[i] = 0;
	}
	caps.n = 0;

	const char *match_end = 0;
	const char *dummy_re = 0;
	if (re[0] == '^') {
		mc_u32 nc = 0;
		int r = mc_re_match_here(re + 1, text, flags, 0, &dummy_re, &match_end, &caps, 0, &nc);
		if (r < 0) return -1;
		if (r == 1) {
			*out_start = text;
			*out_end = match_end;
			if (out_caps) *out_caps = caps;
			return 1;
		}
		return 0;
	}

	for (const char *t = text;; t++) {
		struct mc_regex_caps caps_try = caps;
		mc_u32 nc = 0;
		int r = mc_re_match_here(re, t, flags, 0, &dummy_re, &match_end, &caps_try, 0, &nc);
		if (r < 0) return -1;
		if (r == 1) {
			*out_start = t;
			*out_end = match_end;
			if (out_caps) *out_caps = caps_try;
			return 1;
		}
		if (*t == 0) break;
	}
	return 0;
}
