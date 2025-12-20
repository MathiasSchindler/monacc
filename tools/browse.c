#include "mc.h"

#define BROWSE_MAX_LINKS 256u
#define BROWSE_MAX_HREF 2048u

#define OUT_BUF_CAP 4096u

struct out {
	char buf[OUT_BUF_CAP];
	mc_usize len;
	mc_u8 started; // any non-'\n' output emitted
	mc_u32 nl_tail; // number of consecutive '\n' at end (0..2)
};

static void out_flush(struct out *o) {
	if (!o || o->len == 0) return;
	(void)mc_write_all(1, o->buf, o->len);
	o->len = 0;
}

static void out_byte(struct out *o, char c) {
	if (!o) return;
	if (o->len >= OUT_BUF_CAP) out_flush(o);
	o->buf[o->len++] = c;
	if (c != '\n') o->started = 1;
	if (c == '\n') {
		if (o->nl_tail < 2) o->nl_tail++;
	} else {
		o->nl_tail = 0;
	}
}

static void out_bytes(struct out *o, const char *s, mc_usize n) {
	if (!o || (!s && n)) return;
	for (mc_usize i = 0; i < n; i++) out_byte(o, s[i]);
}

static void out_cstr(struct out *o, const char *s) {
	if (!s) return;
	out_bytes(o, s, mc_strlen(s));
}

static void out_newline(struct out *o) {
	if (!o) return;
	if (!o->started) return;
	if (o->len == 0 && o->nl_tail == 0) {
		out_byte(o, '\n');
		return;
	}
	if (o->nl_tail == 0) out_byte(o, '\n');
}

static void out_blankline(struct out *o) {
	if (!o) return;
	if (!o->started) return;
	if (o->nl_tail == 0) {
		out_byte(o, '\n');
		out_byte(o, '\n');
		return;
	}
	if (o->nl_tail == 1) {
		out_byte(o, '\n');
		return;
	}
}

static void out_u32_dec(struct out *o, mc_u32 v) {
	char tmp[16];
	mc_usize n = 0;
	if (v == 0) {
		out_byte(o, '0');
		return;
	}
	while (v && n < sizeof(tmp)) {
		tmp[n++] = (char)('0' + (v % 10u));
		v /= 10u;
	}
	for (mc_usize i = 0; i < n; i++) {
		out_byte(o, tmp[n - 1 - i]);
	}
}

static int is_alpha(mc_u8 c) {
	c = mc_tolower_ascii(c);
	return (c >= (mc_u8)'a' && c <= (mc_u8)'z');
}

static int is_space(mc_u8 c) {
	return mc_is_space_ascii(c);
}

static int streq_ci_n(const char *a, const char *b, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) {
		mc_u8 ca = mc_tolower_ascii((mc_u8)a[i]);
		mc_u8 cb = mc_tolower_ascii((mc_u8)b[i]);
		if (ca != cb) return 0;
	}
	return 1;
}

static int starts_with_ci(const char *s, const char *pre) {
	mc_usize i = 0;
	while (pre[i]) {
		mc_u8 a = mc_tolower_ascii((mc_u8)s[i]);
		mc_u8 b = mc_tolower_ascii((mc_u8)pre[i]);
		if (a != b) return 0;
		i++;
	}
	return 1;
}

struct links {
	char href[BROWSE_MAX_LINKS][BROWSE_MAX_HREF];
	mc_u16 href_len[BROWSE_MAX_LINKS];
	mc_u16 n;
};

enum mode {
	MODE_TEXT = 0,
	MODE_TAG = 1,
	MODE_ENTITY = 2,
	MODE_COMMENT = 3,
};

enum skip_kind {
	SKIP_NONE = 0,
	SKIP_SCRIPT = 1,
	SKIP_STYLE = 2,
};

struct html {
	struct out out;
	struct links links;
	enum mode mode;
	enum skip_kind skip;
	mc_u8 in_pre;
	mc_u8 pending_space;
	mc_u8 in_a;
	mc_u16 cur_link; // 1-based
	mc_u8 comment_m; // match state for "-->"
	mc_u32 list_depth;
	char tagbuf[1024];
	mc_u32 taglen;
	char entbuf[32];
	mc_u32 entlen;
};

static void html_init(struct html *h) {
	mc_memset(h, 0, sizeof(*h));
	h->mode = MODE_TEXT;
	h->skip = SKIP_NONE;
}

static void emit_indent(struct html *h) {
	if (!h) return;
	mc_u32 depth = h->list_depth;
	if (depth == 0) return;
	mc_u32 spaces = (depth > 0) ? (2u * (depth - 1u)) : 0u;
	for (mc_u32 i = 0; i < spaces; i++) out_byte(&h->out, ' ');
}

static void emit_text_byte(struct html *h, char c) {
	if (!h) return;
	out_byte(&h->out, c);
}

static void emit_text(struct html *h, const char *s, mc_usize n) {
	if (!h) return;
	out_bytes(&h->out, s, n);
}

static void emit_space_if_needed(struct html *h) {
	if (!h) return;
	if (!h->pending_space) return;
	h->pending_space = 0;
	// If we are at a fresh line (newline tail > 0), do not emit a leading space.
	if (h->out.nl_tail) return;
	if (h->out.len == 0) return;
	emit_text_byte(h, ' ');
}

static void emit_text_char(struct html *h, mc_u8 c) {
	if (!h) return;
	if (h->skip != SKIP_NONE) return;

	if (h->in_pre) {
		emit_text_byte(h, (char)c);
		return;
	}

	if (is_space(c)) {
		h->pending_space = 1;
		return;
	}

	emit_space_if_needed(h);
	emit_text_byte(h, (char)c);
}

static int decode_named_entity(const char *name, mc_u32 n, char *out_ch) {
	if (!out_ch) return 0;
	// Common named entities only.
	if (n == 2 && streq_ci_n(name, "lt", 2)) {
		*out_ch = '<';
		return 1;
	}
	if (n == 2 && streq_ci_n(name, "gt", 2)) {
		*out_ch = '>';
		return 1;
	}
	if (n == 3 && streq_ci_n(name, "amp", 3)) {
		*out_ch = '&';
		return 1;
	}
	if (n == 4 && streq_ci_n(name, "quot", 4)) {
		*out_ch = '"';
		return 1;
	}
	if (n == 4 && streq_ci_n(name, "apos", 4)) {
		*out_ch = '\'';
		return 1;
	}
	return 0;
}

static int hex_val(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (int)(c - (mc_u8)'0');
	c = mc_tolower_ascii(c);
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return 10 + (int)(c - (mc_u8)'a');
	return -1;
}

static void flush_entity_literal(struct html *h) {
	if (!h) return;
	emit_text_char(h, (mc_u8)'&');
	for (mc_u32 i = 0; i < h->entlen; i++) emit_text_char(h, (mc_u8)h->entbuf[i]);
	h->entlen = 0;
	h->mode = MODE_TEXT;
}

static void handle_entity(struct html *h) {
	if (!h) return;
	if (h->entlen == 0) {
		emit_text_char(h, (mc_u8)'&');
		return;
	}

	const char *p = h->entbuf;
	mc_u32 n = h->entlen;
	char outc = 0;

	if (p[0] == '#') {
		mc_u32 v = 0;
		mc_u32 i = 1;
		int is_hex = 0;
		if (i < n && (p[i] == 'x' || p[i] == 'X')) {
			is_hex = 1;
			i++;
		}
		if (i >= n) {
			flush_entity_literal(h);
			return;
		}
		for (; i < n; i++) {
			mc_u8 c = (mc_u8)p[i];
			if (is_hex) {
				int hv = hex_val(c);
				if (hv < 0) {
					flush_entity_literal(h);
					return;
				}
				v = (v << 4) | (mc_u32)hv;
			} else {
				if (c < (mc_u8)'0' || c > (mc_u8)'9') {
					flush_entity_literal(h);
					return;
				}
				v = v * 10u + (mc_u32)(c - (mc_u8)'0');
			}
			if (v > 255u) {
				// Keep it byte-oriented for now.
				v = '?';
			}
		}
		outc = (char)(mc_u8)v;
		emit_text_char(h, (mc_u8)outc);
		return;
	}

	if (decode_named_entity(p, n, &outc)) {
		emit_text_char(h, (mc_u8)outc);
		return;
	}

	flush_entity_literal(h);
}

static void link_add(struct html *h, const char *href, mc_u32 href_len) {
	if (!h) return;
	h->cur_link = 0;
	h->in_a = 0;
	if (!href || href_len == 0) return;
	if (h->links.n >= (mc_u16)BROWSE_MAX_LINKS) return;
	if (href_len >= BROWSE_MAX_HREF) href_len = BROWSE_MAX_HREF - 1u;
	mc_u16 idx = h->links.n;
	for (mc_u32 i = 0; i < href_len; i++) h->links.href[idx][i] = href[i];
	h->links.href[idx][href_len] = 0;
	h->links.href_len[idx] = (mc_u16)href_len;
	h->links.n++;
	h->cur_link = (mc_u16)(idx + 1);
	h->in_a = 1;
}

static int parse_href_from_tag(const char *tag, mc_u32 taglen, const char **out_href, mc_u32 *out_len) {
	if (!tag || !out_href || !out_len) return 0;
	*out_href = 0;
	*out_len = 0;

	mc_u32 i = 0;
	while (i + 4u <= taglen) {
		if (!streq_ci_n(tag + i, "href", 4)) {
			i++;
			continue;
		}
		mc_u32 j = i + 4u;
		while (j < taglen && (tag[j] == ' ' || tag[j] == '\t' || tag[j] == '\r' || tag[j] == '\n')) j++;
		if (j >= taglen || tag[j] != '=') {
			i++;
			continue;
		}
		j++;
		while (j < taglen && (tag[j] == ' ' || tag[j] == '\t' || tag[j] == '\r' || tag[j] == '\n')) j++;
		if (j >= taglen) return 0;

		char q = tag[j];
		if (q == '\'' || q == '"') {
			j++;
			mc_u32 start = j;
			while (j < taglen && tag[j] != q) j++;
			if (j <= taglen) {
				*out_href = tag + start;
				*out_len = j - start;
				return 1;
			}
			return 0;
		}

		mc_u32 start = j;
		while (j < taglen) {
			char c = tag[j];
			if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
			j++;
		}
		*out_href = tag + start;
		*out_len = j - start;
		return 1;
	}
	return 0;
}

static void handle_tag(struct html *h, const char *tag, mc_u32 taglen) {
	if (!h || !tag) return;

	// Trim leading whitespace.
	mc_u32 i = 0;
	while (i < taglen && (tag[i] == ' ' || tag[i] == '\t' || tag[i] == '\r' || tag[i] == '\n')) i++;
	if (i >= taglen) return;

	// Special cases:
	if (tag[i] == '!') {
		// <!DOCTYPE ...> or similar: ignore.
		return;
	}

	int closing = 0;
	if (tag[i] == '/') {
		closing = 1;
		i++;
		while (i < taglen && (tag[i] == ' ' || tag[i] == '\t' || tag[i] == '\r' || tag[i] == '\n')) i++;
		if (i >= taglen) return;
	}

	char name[16];
	mc_u32 n = 0;
	while (i < taglen && n + 1u < sizeof(name)) {
		mc_u8 c = (mc_u8)tag[i];
		if (!is_alpha(c) && !(c >= (mc_u8)'0' && c <= (mc_u8)'9')) break;
		name[n++] = (char)mc_tolower_ascii(c);
		i++;
	}
	name[n] = 0;
	if (n == 0) return;

	// While skipping script/style content, only pay attention to the closing tag.
	if (h->skip != SKIP_NONE) {
		if (closing) {
			if (h->skip == SKIP_SCRIPT && mc_streq(name, "script")) h->skip = SKIP_NONE;
			if (h->skip == SKIP_STYLE && mc_streq(name, "style")) h->skip = SKIP_NONE;
		}
		return;
	}

	// script/style: start skipping.
	if (!closing && mc_streq(name, "script")) {
		h->skip = SKIP_SCRIPT;
		return;
	}
	if (!closing && mc_streq(name, "style")) {
		h->skip = SKIP_STYLE;
		return;
	}

	if (mc_streq(name, "br") && !closing) {
		out_newline(&h->out);
		h->pending_space = 0;
		return;
	}

	if ((mc_streq(name, "p") || mc_streq(name, "div")) && !closing) {
		out_blankline(&h->out);
		h->pending_space = 0;
		return;
	}
	if ((mc_streq(name, "p") || mc_streq(name, "div")) && closing) {
		out_newline(&h->out);
		h->pending_space = 0;
		return;
	}

	if (name[0] == 'h' && name[1] >= '1' && name[1] <= '6' && name[2] == 0 && !closing) {
		out_blankline(&h->out);
		h->pending_space = 0;
		return;
	}
	if (name[0] == 'h' && name[1] >= '1' && name[1] <= '6' && name[2] == 0 && closing) {
		out_newline(&h->out);
		h->pending_space = 0;
		return;
	}

	if ((mc_streq(name, "ul") || mc_streq(name, "ol")) && !closing) {
		if (h->list_depth < 8u) h->list_depth++;
		return;
	}
	if ((mc_streq(name, "ul") || mc_streq(name, "ol")) && closing) {
		if (h->list_depth) h->list_depth--;
		return;
	}

	if (mc_streq(name, "li") && !closing) {
		out_newline(&h->out);
		emit_indent(h);
		emit_text(h, "- ", 2);
		h->pending_space = 0;
		return;
	}
	if (mc_streq(name, "li") && closing) {
		out_newline(&h->out);
		h->pending_space = 0;
		return;
	}

	if (mc_streq(name, "pre") && !closing) {
		out_newline(&h->out);
		h->in_pre = 1;
		h->pending_space = 0;
		return;
	}
	if (mc_streq(name, "pre") && closing) {
		h->in_pre = 0;
		out_newline(&h->out);
		h->pending_space = 0;
		return;
	}

	if (mc_streq(name, "a") && !closing) {
		const char *href = 0;
		mc_u32 href_len = 0;
		if (parse_href_from_tag(tag, taglen, &href, &href_len)) {
			link_add(h, href, href_len);
		} else {
			h->in_a = 1;
			h->cur_link = 0;
		}
		return;
	}
	if (mc_streq(name, "a") && closing) {
		if (h->in_a && h->cur_link) {
			emit_text_byte(h, '[');
			out_u32_dec(&h->out, (mc_u32)h->cur_link);
			emit_text_byte(h, ']');
		}
		h->in_a = 0;
		h->cur_link = 0;
		return;
	}

	(void)closing;
}

static void html_feed_byte(struct html *h, mc_u8 c);

static void comment_feed_byte(struct html *h, mc_u8 c) {
	// Match "-->".
	if (!h) return;
	if (h->comment_m == 0) {
		h->comment_m = (c == (mc_u8)'-') ? 1 : 0;
		return;
	}
	if (h->comment_m == 1) {
		if (c == (mc_u8)'-') h->comment_m = 2;
		else h->comment_m = 0;
		return;
	}
	// comment_m == 2
	if (c == (mc_u8)'>') {
		h->mode = MODE_TEXT;
		h->comment_m = 0;
		return;
	}
	// Stay in state 2 if we see more '-', else reset.
	h->comment_m = (c == (mc_u8)'-') ? 2 : 0;
}

static void html_feed_byte(struct html *h, mc_u8 c) {
	if (!h) return;

	for (;;) {
		switch (h->mode) {
		case MODE_TEXT:
			if (c == (mc_u8)'<') {
				h->mode = MODE_TAG;
				h->taglen = 0;
				return;
			}
			if (c == (mc_u8)'&' && h->skip == SKIP_NONE) {
				h->mode = MODE_ENTITY;
				h->entlen = 0;
				return;
			}
			emit_text_char(h, c);
			return;

		case MODE_TAG:
			if (h->taglen < (mc_u32)sizeof(h->tagbuf)) {
				h->tagbuf[h->taglen++] = (char)c;
			}

			// Detect comment start: "!--" immediately after '<'.
			if (h->taglen == 3u && h->tagbuf[0] == '!' && h->tagbuf[1] == '-' && h->tagbuf[2] == '-') {
				h->mode = MODE_COMMENT;
				h->comment_m = 0;
				h->taglen = 0;
				return;
			}

			if (c == (mc_u8)'>') {
				// Process tagbuf excluding the final '>'
				if (h->taglen > 0) h->taglen--;
				handle_tag(h, h->tagbuf, h->taglen);
				h->mode = MODE_TEXT;
				h->taglen = 0;
				return;
			}
			return;

		case MODE_ENTITY:
			if (c == (mc_u8)';') {
				handle_entity(h);
				h->mode = MODE_TEXT;
				h->entlen = 0;
				return;
			}
			if (c == (mc_u8)'<' || c == (mc_u8)'&' || is_space(c) || h->entlen + 1u >= (mc_u32)sizeof(h->entbuf)) {
				flush_entity_literal(h);
				// Re-process this byte as normal text/tag/entity.
				html_feed_byte(h, c);
				return;
			}
			h->entbuf[h->entlen++] = (char)c;
			return;

		case MODE_COMMENT:
			comment_feed_byte(h, c);
			return;
		}
	}
}

static void html_finish(struct html *h) {
	if (!h) return;
	// Flush incomplete entity as literal.
	if (h->mode == MODE_ENTITY) {
		flush_entity_literal(h);
	}
	h->mode = MODE_TEXT;

	out_blankline(&h->out);
	out_cstr(&h->out, "Links:\n");
	for (mc_u16 i = 0; i < h->links.n; i++) {
		out_u32_dec(&h->out, (mc_u32)(i + 1));
		out_byte(&h->out, ' ');
		out_cstr(&h->out, h->links.href[i]);
		out_byte(&h->out, '\n');
	}
	out_flush(&h->out);
}

static int render_html_fd(mc_i32 fd) {
	struct html h;
	html_init(&h);

	mc_u8 buf[4096];
	for (;;) {
		mc_i64 n = mc_sys_read(fd, buf, sizeof(buf));
		if (n < 0) return 1;
		if (n == 0) break;
		for (mc_i64 i = 0; i < n; i++) {
			html_feed_byte(&h, buf[(mc_usize)i]);
		}
	}

	html_finish(&h);
	return 0;
}

static MC_NORETURN void browse_usage(const char *argv0) {
	mc_die_usage(argv0,
		"browse --render-html FILE|-\n"
		"  (WP1) Render local HTML to text and extract links\n"
	);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "browse";

	if (argc < 2 || !argv[1]) browse_usage(argv0);

	if (mc_streq(argv[1], "-h") || mc_streq(argv[1], "--help")) browse_usage(argv0);

	if (mc_streq(argv[1], "--render-html")) {
		if (argc != 3 || !argv[2]) browse_usage(argv0);
		const char *path = argv[2];
		if (mc_streq(path, "-")) {
			return render_html_fd(0);
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		int rc = render_html_fd((mc_i32)fd);
		(void)mc_sys_close((mc_i32)fd);
		return rc;
	}

	// Networking/UI not implemented in WP0/WP1.
	browse_usage(argv0);
	return 2;
}
