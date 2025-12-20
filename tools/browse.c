#include "mc.h"
#include "mc_net.h"

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

// === WP2: URL parsing + HTTP fetch helpers ===

static mc_u16 net_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u16 net_htons(mc_u16 x) {
	return net_bswap16(x);
}

static mc_u16 net_ntohs(mc_u16 x) {
	return net_bswap16(x);
}

static int net_hexval(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (int)(c - (mc_u8)'0');
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return 10 + (int)(c - (mc_u8)'a');
	if (c >= (mc_u8)'A' && c <= (mc_u8)'F') return 10 + (int)(c - (mc_u8)'A');
	return -1;
}

// Strict IPv6 literal parser.
// Supports :: compression. No IPv4-embedded form. No zone index (%eth0).
static int net_parse_ipv6_literal(const char *s, mc_u8 out[16]) {
	if (!s || !*s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p == '%') return 0;
	}

	mc_u16 words[8];
	for (int i = 0; i < 8; i++) words[i] = 0;
	int nwords = 0;
	int compress_at = -1;

	const char *p = s;
	if (*p == ':') {
		p++;
		if (*p != ':') return 0;
		compress_at = 0;
		p++;
	}

	while (*p) {
		if (nwords >= 8) return 0;

		mc_u32 v = 0;
		int nd = 0;
		while (*p) {
			int hv = net_hexval((mc_u8)*p);
			if (hv < 0) break;
			v = (v << 4) | (mc_u32)hv;
			nd++;
			if (nd > 4) return 0;
			p++;
		}
		if (nd == 0) return 0;
		words[nwords++] = (mc_u16)v;

		if (*p == 0) break;
		if (*p != ':') return 0;
		p++;
		if (*p == 0) return 0;
		if (*p == ':') {
			if (compress_at >= 0) return 0;
			compress_at = nwords;
			p++;
			if (*p == 0) break;
		}
	}

	if (compress_at >= 0) {
		int zeros = 8 - nwords;
		if (zeros < 0) return 0;
		for (int i = nwords - 1; i >= compress_at; i--) {
			words[i + zeros] = words[i];
		}
		for (int i = 0; i < zeros; i++) {
			words[compress_at + i] = 0;
		}
		nwords = 8;
	}

	if (nwords != 8) return 0;

	for (int i = 0; i < 8; i++) {
		out[i * 2 + 0] = (mc_u8)((words[i] >> 8) & 0xFFu);
		out[i * 2 + 1] = (mc_u8)(words[i] & 0xFFu);
	}
	return 1;
}

static int net_resolv_conf_pick_v6(mc_u8 out_server[16]) {
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/etc/resolv.conf", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) return 0;

	char buf[4096];
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1);
	(void)mc_sys_close((mc_i32)fd);
	if (n <= 0) return 0;
	buf[(mc_usize)n] = 0;

	const char *p = buf;
	while (*p) {
		const char *line = p;
		while (*p && *p != '\n') p++;
		const char *end = p;
		if (*p == '\n') p++;

		while (line < end && (*line == ' ' || *line == '\t')) line++;
		if (line >= end || *line == '#') continue;

		const char *kw = "nameserver";
		mc_usize kwlen = 10;
		if ((mc_usize)(end - line) < kwlen) continue;
		int ok = 1;
		for (mc_usize i = 0; i < kwlen; i++) {
			if (line[i] != kw[i]) {
				ok = 0;
				break;
			}
		}
		if (!ok) continue;
		const char *q = line + kwlen;
		if (q >= end || !(*q == ' ' || *q == '\t')) continue;
		while (q < end && (*q == ' ' || *q == '\t')) q++;
		if (q >= end) continue;

		const char *tok = q;
		while (q < end && !(*q == ' ' || *q == '\t' || *q == '#')) q++;
		mc_usize tlen = (mc_usize)(q - tok);
		if (tlen == 0 || tlen >= 128) continue;
		char tmp[128];
		for (mc_usize i = 0; i < tlen; i++) tmp[i] = tok[i];
		tmp[tlen] = 0;
		if (net_parse_ipv6_literal(tmp, out_server)) {
			return 1;
		}
	}

	return 0;
}

static mc_u16 net_dns_pick_id(void) {
	mc_u16 id = 0;
	mc_i64 r = mc_sys_getrandom(&id, sizeof(id), 0);
	if (r == (mc_i64)sizeof(id) && id != 0) return id;

	struct mc_timespec ts;
	(void)mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &ts);
	mc_u64 mix = (mc_u64)ts.tv_nsec ^ ((mc_u64)ts.tv_sec << 32) ^ (mc_u64)(mc_usize)(void *)&id;
	id = (mc_u16)(mix & 0xFFFFu);
	if (id == 0) id = 1;
	return id;
}

static int net_dns_encode_qname(mc_u8 *dst, mc_usize cap, const char *name, mc_usize *io_off) {
	mc_usize off = *io_off;
	const char *p = name;
	while (*p) {
		const char *label = p;
		mc_usize len = 0;
		while (*p && *p != '.') {
			len++;
			p++;
			if (len > 63) return 0;
		}
		if (off + 1 + len >= cap) return 0;
		dst[off++] = (mc_u8)len;
		for (mc_usize i = 0; i < len; i++) dst[off++] = (mc_u8)label[i];
		if (*p == '.') p++;
	}
	if (off + 1 > cap) return 0;
	dst[off++] = 0;
	*io_off = off;
	return 1;
}

static int net_dns_name_skip(const mc_u8 *msg, mc_usize msglen, mc_usize off, mc_usize *out_off) {
	mc_usize o = off;
	for (;;) {
		if (o >= msglen) return 0;
		mc_u8 len = msg[o++];
		if (len == 0) {
			*out_off = o;
			return 1;
		}
		if ((len & 0xC0u) == 0xC0u) {
			if (o >= msglen) return 0;
			o++;
			*out_off = o;
			return 1;
		}
		if (len > 63) return 0;
		if (o + len > msglen) return 0;
		o += len;
	}
}

static mc_i64 net_read_line(mc_i32 fd, char *line, mc_usize cap, mc_u8 *buf, mc_usize *io_have, mc_usize *io_off) {
	mc_usize n = 0;
	for (;;) {
		for (mc_usize i = *io_off; i < *io_have; i++) {
			if (buf[i] == (mc_u8)'\n') {
				mc_usize end = i;
				mc_usize start = *io_off;
				mc_usize len = end - start;
				if (len > 0 && buf[end - 1] == (mc_u8)'\r') len--;
				if (len + 1 > cap) return (mc_i64)-MC_EINVAL;
				for (mc_usize k = 0; k < len; k++) line[k] = (char)buf[start + k];
				line[len] = 0;
				*io_off = i + 1;
				return (mc_i64)len;
			}
		}

		(void)n;
		if (*io_off > 0) {
			mc_usize rem = *io_have - *io_off;
			for (mc_usize k = 0; k < rem; k++) buf[k] = buf[*io_off + k];
			*io_have = rem;
			*io_off = 0;
		}
		mc_i64 r = mc_sys_read(fd, buf + *io_have, 4096 - *io_have);
		if (r < 0) return r;
		if (r == 0) {
			if (n == 0) return 0;
			return (mc_i64)-MC_EINVAL;
		}
		*io_have += (mc_usize)r;
	}
}

static int net_dns6_resolve_first_aaaa(const char *argv0, const mc_u8 server_ip[16], mc_u16 server_port, const char *name, mc_u32 timeout_ms,
	mc_u8 out_ip[16]) {
	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = net_htons(server_port);
	for (int i = 0; i < 16; i++) sa.sin6_addr.s6_addr[i] = server_ip[i];

	for (int attempt = 0; attempt < 2; attempt++) {
		int use_tcp = (attempt == 1);
		mc_i32 stype = use_tcp ? MC_SOCK_STREAM : MC_SOCK_DGRAM;
		mc_i32 proto = use_tcp ? MC_IPPROTO_TCP : MC_IPPROTO_UDP;

		mc_i64 fd = mc_sys_socket(MC_AF_INET6, stype | MC_SOCK_CLOEXEC, proto);
		if (fd < 0) mc_die_errno(argv0, "socket", fd);

		mc_i64 r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

		mc_u8 q[512];
		mc_usize qn = 12;
		mc_u16 id = net_dns_pick_id();
		q[0] = (mc_u8)(id >> 8);
		q[1] = (mc_u8)(id & 0xFFu);
		q[2] = 0x01;
		q[3] = 0x00;
		q[4] = 0;
		q[5] = 1;
		q[6] = 0;
		q[7] = 0;
		q[8] = 0;
		q[9] = 0;
		q[10] = 0;
		q[11] = 0;

		if (!net_dns_encode_qname(q, sizeof(q), name, &qn)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		if (qn + 4 > sizeof(q)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		q[qn++] = 0x00;
		q[qn++] = 0x1c;
		q[qn++] = 0x00;
		q[qn++] = 0x01;

		mc_u8 tcpbuf[2 + sizeof(q)];
		const void *sendbuf = q;
		mc_usize sendlen = qn;
		if (use_tcp) {
			tcpbuf[0] = (mc_u8)((qn >> 8) & 0xFFu);
			tcpbuf[1] = (mc_u8)(qn & 0xFFu);
			for (mc_usize i = 0; i < qn; i++) tcpbuf[2 + i] = q[i];
			sendbuf = tcpbuf;
			sendlen = 2 + qn;
		}

		mc_i64 wr = mc_write_all((mc_i32)fd, sendbuf, sendlen);
		if (wr < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

		// Poll for read readiness.
		struct mc_pollfd pfd;
		pfd.fd = (mc_i32)fd;
		pfd.events = MC_POLLIN;
		pfd.revents = 0;
		for (;;) {
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr < 0) {
				if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			if (pr == 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 0;
			}
			break;
		}

		mc_u8 ans[2048];
		mc_i64 nr = mc_sys_read((mc_i32)fd, ans, sizeof(ans));
		(void)mc_sys_close((mc_i32)fd);
		if (nr <= 0) return 0;
		mc_usize msglen = (mc_usize)nr;

		mc_usize off = 0;
		if (use_tcp) {
			if (msglen < 2) return 0;
			mc_u16 tcp_len = (mc_u16)(((mc_u16)ans[0] << 8) | (mc_u16)ans[1]);
			off = 2;
			if ((mc_usize)tcp_len + 2 > msglen) return 0;
			msglen = (mc_usize)tcp_len + 2;
		}
		if (msglen - off < 12) return 0;
		const mc_u8 *msg = ans + off;
		mc_usize mlen = msglen - off;
		mc_u16 rid = (mc_u16)(((mc_u16)msg[0] << 8) | (mc_u16)msg[1]);
		if (rid != id) return 0;
		mc_u8 flags1 = msg[2];
		mc_u8 flags2 = msg[3];
		int tc = (flags2 & 0x02) != 0;
		mc_u16 qd = (mc_u16)(((mc_u16)msg[4] << 8) | (mc_u16)msg[5]);
		mc_u16 an = (mc_u16)(((mc_u16)msg[6] << 8) | (mc_u16)msg[7]);
		mc_u16 ns = (mc_u16)(((mc_u16)msg[8] << 8) | (mc_u16)msg[9]);
		mc_u16 ar = (mc_u16)(((mc_u16)msg[10] << 8) | (mc_u16)msg[11]);
		(void)flags1;

		mc_usize doff = 12;
		for (mc_u16 qi = 0; qi < qd; qi++) {
			mc_usize noff;
			if (!net_dns_name_skip(msg, mlen, doff, &noff)) return 0;
			doff = noff;
			if (doff + 4 > mlen) return 0;
			doff += 4;
		}

		mc_u32 total = (mc_u32)an + (mc_u32)ns + (mc_u32)ar;
		for (mc_u32 ai = 0; ai < total; ai++) {
			mc_usize noff;
			if (!net_dns_name_skip(msg, mlen, doff, &noff)) return 0;
			doff = noff;
			if (doff + 10 > mlen) return 0;
			mc_u16 atype = (mc_u16)(((mc_u16)msg[doff] << 8) | (mc_u16)msg[doff + 1]);
			mc_u16 rdlen = (mc_u16)(((mc_u16)msg[doff + 8] << 8) | (mc_u16)msg[doff + 9]);
			doff += 10;
			if (doff + rdlen > mlen) return 0;
			if (atype == 28 && rdlen == 16) {
				for (int k = 0; k < 16; k++) out_ip[k] = msg[doff + (mc_usize)k];
				return 1;
			}
			doff += rdlen;
		}

		if (!use_tcp && tc) {
			continue;
		}
	}

	return 0;
}

enum url_scheme {
	URL_HTTP = 0,
	URL_HTTPS = 1,
};

struct url {
	enum url_scheme scheme;
	const char *host;
	mc_usize host_len;
	mc_u16 port;
	const char *path;
};

static int net_is_alpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int parse_url_small(const char *in, struct url *out) {
	if (!in || !*in || !out) return 0;
	mc_memset(out, 0, sizeof(*out));
	out->scheme = URL_HTTP;
	out->port = 80;
	out->path = "/";

	const char *p = in;
	const char *s = p;
	while (*p && net_is_alpha(*p)) p++;
	if (*p == ':' && p[1] == '/' && p[2] == '/') {
		mc_usize slen = (mc_usize)(p - s);
		if (slen == 4 && (s[0] == 'h' || s[0] == 'H') && (s[1] == 't' || s[1] == 'T') && (s[2] == 't' || s[2] == 'T') &&
			(s[3] == 'p' || s[3] == 'P')) {
			out->scheme = URL_HTTP;
			out->port = 80;
			p += 3;
		} else if (slen == 5 && (s[0] == 'h' || s[0] == 'H') && (s[1] == 't' || s[1] == 'T') && (s[2] == 't' || s[2] == 'T') &&
			(s[3] == 'p' || s[3] == 'P') && (s[4] == 's' || s[4] == 'S')) {
			out->scheme = URL_HTTPS;
			out->port = 443;
			p += 3;
		} else {
			return 0;
		}
	} else {
		p = in;
	}

	if (*p == 0) return 0;

	if (*p == '[') {
		p++;
		const char *h0 = p;
		while (*p && *p != ']') p++;
		if (*p != ']') return 0;
		out->host = h0;
		out->host_len = (mc_usize)(p - h0);
		p++;
	} else {
		const char *h0 = p;
		while (*p && *p != '/' && *p != ':') p++;
		out->host = h0;
		out->host_len = (mc_usize)(p - h0);
	}
	if (out->host_len == 0 || out->host_len > 255u) return 0;

	if (*p == ':') {
		p++;
		mc_u32 v = 0;
		const char *q = p;
		if (mc_parse_u32_dec_prefix(&q, &v) != 0) return 0;
		if (v == 0 || v > 65535u) return 0;
		out->port = (mc_u16)v;
		p = q;
	}

	if (*p == 0) {
		out->path = "/";
		return 1;
	}
	if (*p != '/') return 0;
	// Path hard limit: 2048.
	if (mc_strlen(p) > 2048u) return 0;
	out->path = p;
	return 1;
}

static mc_i64 net_write_all_or_die(const char *argv0, mc_i32 fd, const void *buf, mc_usize len) {
	mc_i64 r = mc_write_all(fd, buf, len);
	if (r < 0) mc_die_errno(argv0, "write", r);
	return r;
}

struct http_meta {
	int status;
	int chunked;
	mc_i64 content_len;
	char content_type[128];
};

static void http_meta_init(struct http_meta *m) {
	if (!m) return;
	mc_memset(m, 0, sizeof(*m));
	m->status = 0;
	m->chunked = 0;
	m->content_len = (mc_i64)-1;
	m->content_type[0] = 0;
}

static int http_content_type_is_html(const char *ct) {
	if (!ct || !*ct) return 1; // default to HTML when missing
	// case-insensitive prefix match for "text/html"
	const char *p = ct;
	while (*p == ' ' || *p == '\t') p++;
	return starts_with_ci(p, "text/html");
}

static int parse_http_headers_fd(mc_i32 fd, struct http_meta *meta, mc_u8 *buf, mc_usize *io_have, mc_usize *io_off) {
	char line[1024];
	http_meta_init(meta);

	mc_i64 nline = net_read_line(fd, line, sizeof(line), buf, io_have, io_off);
	if (nline <= 0) return 0;
	// "HTTP/1.1 200 ..."
	const char *sp = line;
	while (*sp && *sp != ' ') sp++;
	while (*sp == ' ') sp++;
	int st = 0;
	while (*sp >= '0' && *sp <= '9') {
		st = st * 10 + (int)(*sp - '0');
		sp++;
		if (st > 999) break;
	}
	meta->status = st;

	for (;;) {
		nline = net_read_line(fd, line, sizeof(line), buf, io_have, io_off);
		if (nline < 0) return 0;
		if (nline == 0) break;

		if (starts_with_ci(line, "content-length:")) {
			const char *p = line + 15;
			while (*p == ' ' || *p == '\t') p++;
			mc_i64 v = 0;
			if (mc_parse_i64_dec(p, &v) == 0 && v >= 0) meta->content_len = v;
			continue;
		}
		if (starts_with_ci(line, "transfer-encoding:")) {
			const char *p = line + 18;
			while (*p == ' ' || *p == '\t') p++;
			if (starts_with_ci(p, "chunked")) meta->chunked = 1;
			continue;
		}
		if (starts_with_ci(line, "content-type:")) {
			const char *p = line + 13;
			while (*p == ' ' || *p == '\t') p++;
			mc_usize n = mc_strlen(p);
			if (n >= sizeof(meta->content_type)) n = sizeof(meta->content_type) - 1;
			for (mc_usize i = 0; i < n; i++) meta->content_type[i] = p[i];
			meta->content_type[n] = 0;
			continue;
		}
	}

	return 1;
}

enum sink_kind {
	SINK_HTML = 0,
	SINK_STDOUT = 1,
	SINK_DISCARD = 2,
};

struct body_sink {
	enum sink_kind kind;
	void *ctx;
};

static void html_feed_bytes(struct html *h, const mc_u8 *buf, mc_usize n) {
	if (!h || !buf) return;
	for (mc_usize i = 0; i < n; i++) html_feed_byte(h, buf[i]);
}

static int sink_write(const struct body_sink *sink, const mc_u8 *buf, mc_usize n) {
	if (!sink || !buf || n == 0) return 0;
	if (sink->kind == SINK_DISCARD) return 0;
	if (sink->kind == SINK_STDOUT) {
		mc_i64 wr = mc_write_all(1, buf, n);
		return (wr < 0) ? 1 : 0;
	}
	if (sink->kind == SINK_HTML) {
		struct html *h = (struct html *)sink->ctx;
		html_feed_bytes(h, buf, n);
		return 0;
	}
	return 1;
}

static int http_decode_chunked_fd(const char *argv0, mc_i32 fd, mc_u8 *buf, mc_usize *io_have, mc_usize *io_off, const struct body_sink *sink) {
	char line[1024];
	for (;;) {
		mc_i64 nline = net_read_line(fd, line, sizeof(line), buf, io_have, io_off);
		if (nline <= 0) return 1;
		mc_u64 sz = 0;
		const char *p = line;
		while (*p && *p != ';') {
			int hv = net_hexval((mc_u8)*p);
			if (hv < 0) break;
			sz = (sz << 4) | (mc_u64)hv;
			p++;
			if (sz > (mc_u64)(1024u * 1024u * 1024u)) return 1;
		}
		if (sz == 0) {
			// trailer headers until blank line
			for (;;) {
				nline = net_read_line(fd, line, sizeof(line), buf, io_have, io_off);
				if (nline <= 0) break;
			}
			break;
		}

		mc_u64 left = sz;
		while (left > 0) {
			if (*io_off < *io_have) {
				mc_usize avail = *io_have - *io_off;
				mc_usize take = avail;
				if ((mc_u64)take > left) take = (mc_usize)left;
				if (sink_write(sink, buf + *io_off, take) != 0) return 1;
				*io_off += take;
				left -= (mc_u64)take;
				continue;
			}
			mc_i64 nr = mc_sys_read(fd, buf, 4096);
			if (nr < 0) mc_die_errno(argv0, "read", nr);
			if (nr == 0) return 1;
			*io_have = (mc_usize)nr;
			*io_off = 0;
		}

		// Consume CRLF after chunk (read line, expected empty)
		char crlf[8];
		mc_i64 cr = net_read_line(fd, crlf, sizeof(crlf), buf, io_have, io_off);
		if (cr < 0) return 1;
	}
	return 0;
}

static int http_stream_body_fd(const char *argv0, mc_i32 fd, const struct http_meta *meta, mc_u8 *buf, mc_usize *io_have, mc_usize *io_off,
	const struct body_sink *sink) {
	if (!meta) return 1;
	if (meta->chunked) {
		return http_decode_chunked_fd(argv0, fd, buf, io_have, io_off, sink);
	}

	// First flush buffered bytes after header parsing.
	if (*io_off < *io_have) {
		mc_usize n = *io_have - *io_off;
		if (sink_write(sink, buf + *io_off, n) != 0) return 1;
		*io_off = *io_have;
	}

	mc_i64 remaining = meta->content_len;
	for (;;) {
		mc_i64 nr = mc_sys_read(fd, buf, 4096);
		if (nr < 0) mc_die_errno(argv0, "read", nr);
		if (nr == 0) break;
		mc_usize wn = (mc_usize)nr;
		if (remaining >= 0 && (mc_i64)wn > remaining) wn = (mc_usize)remaining;
		if (sink_write(sink, buf, wn) != 0) return 1;
		if (remaining >= 0) {
			remaining -= (mc_i64)wn;
			if (remaining <= 0) break;
		}
	}
	return 0;
}

static int http_fetch(const char *argv0, const struct url *u, mc_u32 timeout_ms, struct http_meta *out_meta, int *out_is_html,
	const struct body_sink *html_sink, const struct body_sink *text_sink) {
	if (!argv0 || !u || !u->host || !u->path) return 1;
	if (u->scheme != URL_HTTP) return 1;

	// DNS server
	mc_u8 dns_server[16];
	int have_dns = net_resolv_conf_pick_v6(dns_server);
	if (!have_dns) {
		// Fallback: Google public DNS v6
		(void)net_parse_ipv6_literal("2001:4860:4860::8888", dns_server);
	}

	// Resolve host to IPv6
	mc_u8 host_ip6[16];
	char host_tmp[256];
	if (u->host_len >= sizeof(host_tmp)) return 1;
	for (mc_usize i = 0; i < u->host_len; i++) host_tmp[i] = u->host[i];
	host_tmp[u->host_len] = 0;
	if (!net_parse_ipv6_literal(host_tmp, host_ip6)) {
		if (!net_dns6_resolve_first_aaaa(argv0, dns_server, 53, host_tmp, timeout_ms, host_ip6)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": dns failed\n");
			return 1;
		}
	}

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = net_htons(u->port);
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = host_ip6[k];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	// connect with timeout
	mc_i64 fl = mc_sys_fcntl((mc_i32)fd, MC_F_GETFL, 0);
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
	fl = mc_sys_fcntl((mc_i32)fd, MC_F_SETFL, (mc_i64)((mc_u64)fl | (mc_u64)MC_O_NONBLOCK));
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);

	mc_i64 r = mc_sys_connect((mc_i32)fd, &dst, (mc_u32)sizeof(dst));
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EINPROGRESS) {
		mc_die_errno(argv0, "connect", r);
	}

	struct mc_pollfd pfd;
	pfd.fd = (mc_i32)fd;
	pfd.events = MC_POLLOUT;
	pfd.revents = 0;
	for (;;) {
		mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
		if (pr < 0) {
			if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
			mc_die_errno(argv0, "poll", pr);
		}
		if (pr == 0) {
			mc_print_errno(argv0, "connect", (mc_i64)-MC_ETIMEDOUT);
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
		break;
	}

	r = mc_sys_connect((mc_i32)fd, &dst, (mc_u32)sizeof(dst));
	if (r < 0) {
		mc_u64 e = (mc_u64)(-r);
		if (e != (mc_u64)MC_EISCONN) mc_die_errno(argv0, "connect", r);
	}

	// request
	net_write_all_or_die(argv0, (mc_i32)fd, "GET ", 4);
	net_write_all_or_die(argv0, (mc_i32)fd, u->path, mc_strlen(u->path));
	net_write_all_or_die(argv0, (mc_i32)fd, " HTTP/1.1\r\nHost: ", 17);
	net_write_all_or_die(argv0, (mc_i32)fd, u->host, u->host_len);
	net_write_all_or_die(argv0, (mc_i32)fd, "\r\nUser-Agent: monacc-browse\r\nConnection: close\r\n\r\n", 64);

	// headers
	mc_u8 buf[4096];
	mc_usize have = 0;
	mc_usize off = 0;
	struct http_meta meta;
	if (!parse_http_headers_fd((mc_i32)fd, &meta, buf, &have, &off)) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	if (out_meta) *out_meta = meta;
	int is_html = http_content_type_is_html(meta.content_type);
	if (out_is_html) *out_is_html = is_html;
	if (meta.status < 200 || meta.status >= 300) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	const struct body_sink *sink = is_html ? html_sink : text_sink;
	int rc = http_stream_body_fd(argv0, (mc_i32)fd, &meta, buf, &have, &off, sink);
	(void)mc_sys_close((mc_i32)fd);
	return rc;
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
	mc_u8 emit_text;
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
	h->emit_text = 1;
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
	if (!h->emit_text) return;
	out_byte(&h->out, c);
}

static void emit_text(struct html *h, const char *s, mc_usize n) {
	if (!h) return;
	if (!h->emit_text) return;
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

static int render_html_fd(mc_i32 fd, int emit_text) {
	struct html h;
	html_init(&h);
	h.emit_text = (emit_text != 0);

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
		"browse URL\n"
		"browse -dump-links URL\n"
		"browse --render-html FILE|-\n"
		"browse --parse-url URL\n"
		"browse --parse-http-headers  < headers.txt\n"
		"browse --decode-chunked      < chunked.txt\n"
		"\n"
		"WP1/WP2:\n"
		"  --render-html: offline HTML->text rendering\n"
		"  URL fetch: http:// only for now (https planned in WP4)\n"
	);
}

static int cmd_parse_url(const char *argv0, const char *s) {
	struct url u;
	if (!parse_url_small(s, &u)) browse_usage(argv0);
	if (u.scheme == URL_HTTP) mc_write_str(1, "scheme http\n");
	else mc_write_str(1, "scheme https\n");
	mc_write_str(1, "host ");
	(void)mc_write_all(1, u.host, u.host_len);
	mc_write_str(1, "\nport ");
	(void)mc_write_u64_dec(1, (mc_u64)u.port);
	mc_write_str(1, "\npath ");
	mc_write_str(1, u.path);
	mc_write_str(1, "\n");
	return 0;
}

static int cmd_parse_http_headers(const char *argv0) {
	(void)argv0;
	mc_u8 buf[4096];
	mc_usize have = 0;
	mc_usize off = 0;
	struct http_meta m;
	if (!parse_http_headers_fd(0, &m, buf, &have, &off)) return 1;
	mc_write_str(1, "status ");
	(void)mc_write_i64_dec(1, (mc_i64)m.status);
	mc_write_str(1, "\n");
	if (m.content_type[0]) {
		mc_write_str(1, "content-type ");
		mc_write_str(1, m.content_type);
		mc_write_str(1, "\n");
	} else {
		mc_write_str(1, "content-type -\n");
	}
	mc_write_str(1, "content-length ");
	(void)mc_write_i64_dec(1, (mc_i64)m.content_len);
	mc_write_str(1, "\n");
	mc_write_str(1, "chunked ");
	(void)mc_write_u64_dec(1, (mc_u64)m.chunked);
	mc_write_str(1, "\n");
	return 0;
}

static int cmd_decode_chunked(const char *argv0) {
	mc_u8 buf[4096];
	mc_usize have = 0;
	mc_usize off = 0;
	struct body_sink sink;
	sink.kind = SINK_STDOUT;
	sink.ctx = 0;
	return http_decode_chunked_fd(argv0, 0, buf, &have, &off, &sink);
}

static int cmd_fetch_and_render(const char *argv0, const char *url_s, int dump_links_only) {
	struct url u;
	if (!parse_url_small(url_s, &u)) browse_usage(argv0);
	if (u.scheme == URL_HTTPS) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": https not implemented yet (WP4)\n");
		return 1;
	}

	struct http_meta meta;
	mc_u32 timeout_ms = 5000;
	int is_html = 1;

	if (dump_links_only) {
		// If content-type isn't HTML, emit an empty link table.
		struct html h;
		html_init(&h);
		h.emit_text = 0;
		struct body_sink html_sink;
		html_sink.kind = SINK_HTML;
		html_sink.ctx = &h;
		struct body_sink text_sink;
		text_sink.kind = SINK_DISCARD;
		text_sink.ctx = 0;
		int rc = http_fetch(argv0, &u, timeout_ms, &meta, &is_html, &html_sink, &text_sink);
		if (rc != 0) return rc;
		if (is_html) {
			html_finish(&h);
			return 0;
		}
		mc_write_str(1, "Links:\n");
		return 0;
	}

	struct html h;
	html_init(&h);
	struct body_sink html_sink;
	html_sink.kind = SINK_HTML;
	html_sink.ctx = &h;
	struct body_sink text_sink;
	text_sink.kind = SINK_STDOUT;
	text_sink.ctx = 0;

	int rc = http_fetch(argv0, &u, timeout_ms, &meta, &is_html, &html_sink, &text_sink);
	if (rc != 0) return rc;
	if (is_html) {
		html_finish(&h);
		return 0;
	}
	// Plain text: body already written to stdout.
	mc_write_str(1, "\n\nLinks:\n");
	return 0;
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
			return render_html_fd(0, 1);
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		int rc = render_html_fd((mc_i32)fd, 1);
		(void)mc_sys_close((mc_i32)fd);
		return rc;
	}

	if (mc_streq(argv[1], "--parse-url")) {
		if (argc != 3 || !argv[2]) browse_usage(argv0);
		return cmd_parse_url(argv0, argv[2]);
	}

	if (mc_streq(argv[1], "--parse-http-headers")) {
		if (argc != 2) browse_usage(argv0);
		return cmd_parse_http_headers(argv0);
	}

	if (mc_streq(argv[1], "--decode-chunked")) {
		if (argc != 2) browse_usage(argv0);
		return cmd_decode_chunked(argv0);
	}

	if (mc_streq(argv[1], "-dump-links")) {
		if (argc != 3 || !argv[2]) browse_usage(argv0);
		return cmd_fetch_and_render(argv0, argv[2], 1);
	}

	// WP2: fetch URL (http:// only)
	if (argc == 2 && argv[1] && argv[1][0] != '-') {
		return cmd_fetch_and_render(argv0, argv[1], 0);
	}

	// Unknown mode
	browse_usage(argv0);
	return 2;
}
