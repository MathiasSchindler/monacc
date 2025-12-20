#include "mc.h"
#include "mc_net.h"
#include "mc_hkdf.h"
#include "mc_sha256.h"
#include "mc_tls13.h"
#include "mc_tls13_handshake.h"
#include "mc_tls13_transcript.h"
#include "mc_tls_record.h"
#include "mc_x25519.h"

#define BROWSE_MAX_LINKS 256u
#define BROWSE_MAX_HREF 2048u

// Shared read buffer size for line-based HTTP parsing.
// Must handle very long headers seen in the wild (e.g. Wikimedia report-to).
#define NET_IOBUF_CAP 16384u

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
				if (cap == 0) return (mc_i64)-MC_EINVAL;
				mc_usize out_len = len;
				if (out_len + 1 > cap) out_len = cap - 1;
				for (mc_usize k = 0; k < out_len; k++) line[k] = (char)buf[start + k];
				line[out_len] = 0;
				*io_off = i + 1;
				return (mc_i64)out_len;
			}
		}

		(void)n;
		if (*io_off > 0) {
			mc_usize rem = *io_have - *io_off;
			for (mc_usize k = 0; k < rem; k++) buf[k] = buf[*io_off + k];
			*io_have = rem;
			*io_off = 0;
		}
		if (*io_have >= NET_IOBUF_CAP) return (mc_i64)-MC_EINVAL;
		mc_i64 r = mc_sys_read(fd, buf + *io_have, NET_IOBUF_CAP - *io_have);
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
	char location[2048];
};

static void http_meta_init(struct http_meta *m) {
	if (!m) return;
	mc_memset(m, 0, sizeof(*m));
	m->status = 0;
	m->chunked = 0;
	m->content_len = (mc_i64)-1;
	m->content_type[0] = 0;
	m->location[0] = 0;
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
		if (starts_with_ci(line, "location:")) {
			const char *p = line + 9;
			while (*p == ' ' || *p == '\t') p++;
			mc_usize n = mc_strlen(p);
			if (n >= sizeof(meta->location)) n = sizeof(meta->location) - 1;
			for (mc_usize i = 0; i < n; i++) meta->location[i] = p[i];
			meta->location[n] = 0;
			continue;
		}
	}

	return 1;
}

static int host_needs_brackets(const char *host, mc_usize host_len) {
	if (!host) return 0;
	for (mc_usize i = 0; i < host_len; i++) {
		if (host[i] == ':') return 1;
	}
	return 0;
}

static int url_is_default_port(enum url_scheme scheme, mc_u16 port) {
	if (scheme == URL_HTTP) return port == 80;
	return port == 443;
}

static int url_format(char *out, mc_usize cap, const struct url *u, const char *path_override) {
	if (!out || cap == 0 || !u || !u->host || u->host_len == 0) return 0;
	const char *path = path_override ? path_override : u->path;
	if (!path || path[0] != '/') return 0;

	mc_usize o = 0;
	const char *scheme = (u->scheme == URL_HTTPS) ? "https" : "http";
	for (mc_usize i = 0; scheme[i]; i++) {
		if (o + 1 >= cap) return 0;
		out[o++] = scheme[i];
	}
	if (o + 3 >= cap) return 0;
	out[o++] = ':';
	out[o++] = '/';
	out[o++] = '/';

	int br = host_needs_brackets(u->host, u->host_len);
	if (br) {
		if (o + 1 >= cap) return 0;
		out[o++] = '[';
	}
	if (o + u->host_len + 1 >= cap) return 0;
	for (mc_usize i = 0; i < u->host_len; i++) out[o++] = u->host[i];
	if (br) {
		if (o + 1 >= cap) return 0;
		out[o++] = ']';
	}
	if (!url_is_default_port(u->scheme, u->port)) {
		char tmp[32];
		mc_usize n = 0;
		mc_u64 v = (mc_u64)u->port;
		if (v == 0) return 0;
		while (v && n + 1 < sizeof(tmp)) {
			tmp[n++] = (char)('0' + (char)(v % 10u));
			v /= 10u;
		}
		if (o + 1 + n >= cap) return 0;
		out[o++] = ':';
		for (mc_usize i = 0; i < n; i++) out[o++] = tmp[n - 1 - i];
	}
	mc_usize plen = mc_strlen(path);
	if (o + plen + 1 >= cap) return 0;
	for (mc_usize i = 0; i < plen; i++) out[o++] = path[i];
	out[o] = 0;
	return 1;
}

static mc_usize path_dir_prefix_len(const char *path) {
	if (!path || path[0] != '/') return 1;
	mc_usize n = mc_strlen(path);
	if (n == 1) return 1;
	if (path[n - 1] == '/') return n;
	for (mc_usize i = n; i > 0; i--) {
		if (path[i - 1] == '/') return i;
	}
	return 1;
}

static int path_normalize_inplace(char *path) {
	// Normalize dot segments in an absolute path. Returns 1 on success.
	if (!path || path[0] != '/') return 0;
	mc_usize n = mc_strlen(path);
	if (n == 1) return 1;

	mc_usize w = 0;
	mc_usize i = 0;
	// Keep leading '/'
	path[w++] = '/';
	i = 1;

	while (i < n) {
		// Skip repeated slashes.
		while (i < n && path[i] == '/') i++;
		if (i >= n) break;

		mc_usize seg_start = i;
		while (i < n && path[i] != '/') i++;
		mc_usize seg_len = i - seg_start;

		if (seg_len == 1 && path[seg_start] == '.') {
			continue;
		}
		if (seg_len == 2 && path[seg_start] == '.' && path[seg_start + 1] == '.') {
			// Pop one segment (but never above root)
			if (w > 1) {
				// Remove trailing '/'
				if (w > 0 && path[w - 1] == '/') w--;
				while (w > 1 && path[w - 1] != '/') w--;
			}
			continue;
		}

		// Write segment
		if (w > 1 && path[w - 1] != '/') path[w++] = '/';
		for (mc_usize k = 0; k < seg_len; k++) path[w++] = path[seg_start + k];
	}

	if (w == 0) {
		path[0] = '/';
		path[1] = 0;
		return 1;
	}
	path[w] = 0;
	return 1;
}

// Resolve a possibly-relative href against a base URL.
// Returns 1 and writes absolute URL to out when resolved; returns 0 to mean "keep raw".
static int resolve_url_against(const struct url *base, const char *href, char *out, mc_usize cap) {
	if (!base || !href || !out || cap == 0) return 0;
	if (starts_with_ci(href, "http://") || starts_with_ci(href, "https://")) {
		// Absolute URL already.
		mc_usize n = mc_strlen(href);
		if (n + 1 > cap) return 0;
		for (mc_usize i = 0; i < n; i++) out[i] = href[i];
		out[n] = 0;
		return 1;
	}
	if (href[0] == 0) return 0;
	if (href[0] == '#') return 0;
	if (href[0] == '/') {
		char tmp[2048];
		mc_usize n = mc_strlen(href);
		if (n + 1 > sizeof(tmp)) return 0;
		for (mc_usize i = 0; i < n; i++) tmp[i] = href[i];
		tmp[n] = 0;
		(void)path_normalize_inplace(tmp);
		return url_format(out, cap, base, tmp);
	}

	// If it looks like a non-http scheme (e.g. mailto:), keep raw.
	for (mc_usize i = 0; href[i]; i++) {
		if (href[i] == '/') break;
		if (href[i] == ':') return 0;
	}

	char joined[2048];
	const char *bp = base->path ? base->path : "/";
	mc_usize dirn = path_dir_prefix_len(bp);
	if (dirn >= sizeof(joined)) return 0;
	for (mc_usize i = 0; i < dirn; i++) joined[i] = bp[i];
	mc_usize o = dirn;
	if (o > 0 && joined[o - 1] != '/') {
		if (o + 1 >= sizeof(joined)) return 0;
		joined[o++] = '/';
	}
	mc_usize hn = mc_strlen(href);
	if (o + hn + 1 >= sizeof(joined)) return 0;
	for (mc_usize i = 0; i < hn; i++) joined[o++] = href[i];
	joined[o] = 0;
	(void)path_normalize_inplace(joined);
	return url_format(out, cap, base, joined);
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
			mc_i64 nr = mc_sys_read(fd, buf, NET_IOBUF_CAP);
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

	// Restore blocking mode for normal I/O.
	fl = mc_sys_fcntl((mc_i32)fd, MC_F_GETFL, 0);
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
	fl = mc_sys_fcntl((mc_i32)fd, MC_F_SETFL, (mc_i64)((mc_u64)fl & ~((mc_u64)MC_O_NONBLOCK)));
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);

	// request
	net_write_all_or_die(argv0, (mc_i32)fd, "GET ", 4);
	net_write_all_or_die(argv0, (mc_i32)fd, u->path, mc_strlen(u->path));
	net_write_all_or_die(argv0, (mc_i32)fd, " HTTP/1.1\r\nHost: ", 17);
	net_write_all_or_die(argv0, (mc_i32)fd, u->host, u->host_len);
	net_write_all_or_die(argv0, (mc_i32)fd, "\r\nUser-Agent: monacc-browse\r\nConnection: close\r\n\r\n", 64);

	// headers
	mc_u8 buf[NET_IOBUF_CAP];
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
	// Let caller handle redirects.
	if (meta.status == 301 || meta.status == 302 || meta.status == 303 || meta.status == 307 || meta.status == 308) {
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}
	if (meta.status < 200 || meta.status >= 300) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	const struct body_sink *sink = is_html ? html_sink : text_sink;
	int rc = http_stream_body_fd(argv0, (mc_i32)fd, &meta, buf, &have, &off, sink);
	(void)mc_sys_close((mc_i32)fd);
	return rc;
}

// === WP4: in-process HTTPS fetch (TLS 1.3, no certificate validation) ===

static const mc_u8 *sha256_empty32_ptr(void) {
	return (const mc_u8 *)
		"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
		"\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
}

static void tls_getrandom_or_die(const char *argv0, void *out, mc_usize n) {
	mc_u8 *p = (mc_u8 *)out;
	mc_usize got = 0;
	while (got < n) {
		mc_i64 r = mc_sys_getrandom(p + got, n - got, 0);
		if (r < 0) mc_die_errno(argv0, "getrandom", r);
		if (r == 0) mc_die_errno(argv0, "getrandom", (mc_i64)-MC_EINVAL);
		got += (mc_usize)r;
	}
}

static int tls_poll_in(mc_i32 fd, mc_u32 timeout_ms) {
	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = MC_POLLIN;
	pfd.revents = 0;
	for (;;) {
		mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
		if (pr < 0) {
			if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
			return 0;
		}
		if (pr == 0) return 0;
		break;
	}
	return (pfd.revents & MC_POLLIN) != 0;
}

static int tls_read_exact_timeout(mc_i32 fd, void *buf, mc_usize len, mc_u32 timeout_ms) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize got = 0;
	while (got < len) {
		if (!tls_poll_in(fd, timeout_ms)) return 0;
		mc_i64 r = mc_sys_read(fd, p + got, len - got);
		if (r < 0) return 0;
		if (r == 0) return 0;
		got += (mc_usize)r;
	}
	return 1;
}

static int tls_record_read(mc_i32 fd, mc_u32 timeout_ms, mc_u8 hdr[5], mc_u8 *payload, mc_usize payload_cap, mc_usize *out_len) {
	if (!hdr || !payload || !out_len) return 0;
	*out_len = 0;
	if (!tls_read_exact_timeout(fd, hdr, 5, timeout_ms)) return 0;
	mc_u16 rlen = (mc_u16)(((mc_u16)hdr[3] << 8) | (mc_u16)hdr[4]);
	if ((mc_usize)rlen > payload_cap) return 0;
	if (!tls_read_exact_timeout(fd, payload, (mc_usize)rlen, timeout_ms)) return 0;
	*out_len = (mc_usize)rlen;
	return 1;
}

static int tls_hs_append(mc_u8 *buf, mc_usize cap, mc_usize *io_len, const mc_u8 *p, mc_usize n) {
	if (!buf || !io_len) return -1;
	if (!p && n) return -1;
	if (*io_len + n > cap) return -1;
	if (n) mc_memcpy(buf + *io_len, p, n);
	*io_len += n;
	return 0;
}

static int tls_hs_consume_one(mc_u8 *buf, mc_usize *io_len, mc_u8 *out_type, mc_u32 *out_body_len, mc_u8 *out_msg, mc_usize out_cap,
	mc_usize *out_msg_len) {
	if (!buf || !io_len || !out_type || !out_body_len || !out_msg || !out_msg_len) return -1;
	if (*io_len < 4u) return 1;
	mc_u8 ht = buf[0];
	mc_u32 hl = ((mc_u32)buf[1] << 16) | ((mc_u32)buf[2] << 8) | (mc_u32)buf[3];
	mc_usize total = 4u + (mc_usize)hl;
	if (total > *io_len) return 1;
	if (total > out_cap) return -1;
	mc_memcpy(out_msg, buf, total);
	*out_type = ht;
	*out_body_len = hl;
	*out_msg_len = total;
	mc_usize rem = *io_len - total;
	if (rem) mc_memmove(buf, buf + total, rem);
	*io_len = rem;
	return 0;
}

static int tcp6_connect_timeout(const char *argv0, const mc_u8 ip6[16], mc_u16 port, mc_u32 timeout_ms, mc_i32 *out_fd) {
	if (!out_fd) return 0;
	*out_fd = -1;

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = net_htons(port);
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = ip6[k];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	mc_i64 fl = mc_sys_fcntl((mc_i32)fd, MC_F_GETFL, 0);
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
	fl = mc_sys_fcntl((mc_i32)fd, MC_F_SETFL, (mc_i64)((mc_u64)fl | (mc_u64)MC_O_NONBLOCK));
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);

	mc_i64 r = mc_sys_connect((mc_i32)fd, &dst, (mc_u32)sizeof(dst));
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EINPROGRESS) {
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	struct mc_pollfd pfd;
	pfd.fd = (mc_i32)fd;
	pfd.events = MC_POLLOUT;
	pfd.revents = 0;
	for (;;) {
		mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
		if (pr < 0) {
			if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		if (pr == 0) {
			mc_print_errno(argv0, "connect", (mc_i64)-MC_ETIMEDOUT);
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		break;
	}

	r = mc_sys_connect((mc_i32)fd, &dst, (mc_u32)sizeof(dst));
	if (r < 0) {
		mc_u64 e = (mc_u64)(-r);
		if (e != (mc_u64)MC_EISCONN) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
	}

	*out_fd = (mc_i32)fd;
	return 1;
}

struct tls_stream {
	mc_i32 fd;
	mc_u32 timeout_ms;
	mc_u8 c_ap_key[16];
	mc_u8 c_ap_iv[12];
	mc_u8 s_ap_key[16];
	mc_u8 s_ap_iv[12];
	mc_u64 c_ap_seq;
	mc_u64 s_ap_seq;
	mc_u8 buf[65536];
	mc_usize off;
	mc_usize have;
};

static int tls_stream_read_some(const char *argv0, struct tls_stream *ts, mc_u8 *out, mc_usize out_cap, mc_usize *out_len) {
	if (!argv0 || !ts || !out_len) return 0;
	*out_len = 0;
	if (out_cap == 0) return 1;

	if (ts->off < ts->have) {
		mc_usize avail = ts->have - ts->off;
		mc_usize take = avail;
		if (take > out_cap) take = out_cap;
		mc_memcpy(out, ts->buf + ts->off, take);
		ts->off += take;
		*out_len = take;
		return 1;
	}

	for (;;) {
		mc_u8 rhdr[5];
		mc_u8 payload[65536];
		mc_usize rlen = 0;
		if (!tls_record_read(ts->fd, ts->timeout_ms, rhdr, payload, sizeof(payload), &rlen)) {
			return 1;
		}
		mc_u8 rtype = rhdr[0];
		if (rtype == MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype == MC_TLS_CONTENT_ALERT) return 1;
		if (rtype != MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5 + 65536];
		mc_usize record_len = 5u + rlen;
		if (record_len > sizeof(record)) return 0;
		mc_memcpy(record, rhdr, 5);
		mc_memcpy(record + 5, payload, rlen);

		mc_u8 inner_type = 0;
		mc_u8 pt[65536];
		mc_usize pt_len = 0;
		if (mc_tls_record_decrypt(ts->s_ap_key, ts->s_ap_iv, ts->s_ap_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) {
			return 0;
		}
		ts->s_ap_seq++;

		if (inner_type == MC_TLS_CONTENT_APPLICATION_DATA) {
			if (pt_len == 0) continue;
			if (pt_len > sizeof(ts->buf)) return 0;
			mc_memcpy(ts->buf, pt, pt_len);
			ts->off = 0;
			ts->have = pt_len;
			break;
		}
		if (inner_type == MC_TLS_CONTENT_ALERT) {
			return 1;
		}
		// Ignore other inner types.
	}

	return tls_stream_read_some(argv0, ts, out, out_cap, out_len);
}

static mc_i64 tls_read_line_stream(const char *argv0, struct tls_stream *ts, char *line, mc_usize cap,
	mc_u8 *buf, mc_usize *io_have, mc_usize *io_off) {
	if (!argv0 || !ts || !line || cap == 0 || !buf || !io_have || !io_off) return (mc_i64)-MC_EINVAL;
	for (;;) {
		for (mc_usize i = *io_off; i < *io_have; i++) {
			if (buf[i] == (mc_u8)'\n') {
				mc_usize end = i;
				mc_usize start = *io_off;
				mc_usize len = end - start;
				if (len > 0 && buf[end - 1] == (mc_u8)'\r') len--;
				mc_usize out_len = len;
				if (out_len + 1 > cap) out_len = cap - 1;
				for (mc_usize k = 0; k < out_len; k++) line[k] = (char)buf[start + k];
				line[out_len] = 0;
				*io_off = i + 1;
				return (mc_i64)out_len;
			}
		}

		if (*io_off > 0) {
			mc_usize rem = *io_have - *io_off;
			for (mc_usize k = 0; k < rem; k++) buf[k] = buf[*io_off + k];
			*io_have = rem;
			*io_off = 0;
		}

		mc_usize rn = 0;
		if (*io_have >= NET_IOBUF_CAP) return (mc_i64)-MC_EINVAL;
		if (!tls_stream_read_some(argv0, ts, buf + *io_have, NET_IOBUF_CAP - *io_have, &rn)) return (mc_i64)-MC_EINVAL;
		if (rn == 0) return 0;
		*io_have += rn;
	}
}

static int parse_http_headers_tls(const char *argv0, struct tls_stream *ts, struct http_meta *meta, mc_u8 *buf, mc_usize *io_have,
	mc_usize *io_off) {
	char line[1024];
	http_meta_init(meta);

	mc_i64 nline = tls_read_line_stream(argv0, ts, line, sizeof(line), buf, io_have, io_off);
	if (nline <= 0) return 0;
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
		nline = tls_read_line_stream(argv0, ts, line, sizeof(line), buf, io_have, io_off);
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
		if (starts_with_ci(line, "location:")) {
			const char *p = line + 9;
			while (*p == ' ' || *p == '\t') p++;
			mc_usize n = mc_strlen(p);
			if (n >= sizeof(meta->location)) n = sizeof(meta->location) - 1;
			for (mc_usize i = 0; i < n; i++) meta->location[i] = p[i];
			meta->location[n] = 0;
			continue;
		}
	}

	return 1;
}

static int http_decode_chunked_tls(const char *argv0, struct tls_stream *ts, mc_u8 *buf, mc_usize *io_have, mc_usize *io_off,
	const struct body_sink *sink) {
	char line[1024];
	for (;;) {
		mc_i64 nline = tls_read_line_stream(argv0, ts, line, sizeof(line), buf, io_have, io_off);
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
			for (;;) {
				nline = tls_read_line_stream(argv0, ts, line, sizeof(line), buf, io_have, io_off);
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
			mc_usize rn = 0;
			if (!tls_stream_read_some(argv0, ts, buf, 4096, &rn)) return 1;
			if (rn == 0) return 1;
			*io_have = rn;
			*io_off = 0;
		}

		char crlf[8];
		mc_i64 cr = tls_read_line_stream(argv0, ts, crlf, sizeof(crlf), buf, io_have, io_off);
		if (cr < 0) return 1;
	}
	return 0;
}

static int http_stream_body_tls(const char *argv0, struct tls_stream *ts, const struct http_meta *meta, mc_u8 *buf, mc_usize *io_have,
	mc_usize *io_off, const struct body_sink *sink) {
	if (!meta) return 1;
	if (meta->chunked) {
		return http_decode_chunked_tls(argv0, ts, buf, io_have, io_off, sink);
	}

	if (*io_off < *io_have) {
		mc_usize n = *io_have - *io_off;
		if (sink_write(sink, buf + *io_off, n) != 0) return 1;
		*io_off = *io_have;
	}

	mc_i64 remaining = meta->content_len;
	for (;;) {
		mc_usize rn = 0;
		if (!tls_stream_read_some(argv0, ts, buf, 4096, &rn)) return 1;
		if (rn == 0) break;
		mc_usize wn = rn;
		if (remaining >= 0 && (mc_i64)wn > remaining) wn = (mc_usize)remaining;
		if (sink_write(sink, buf, wn) != 0) return 1;
		if (remaining >= 0) {
			remaining -= (mc_i64)wn;
			if (remaining <= 0) break;
		}
	}
	return 0;
}

static int https_fetch(const char *argv0, const struct url *u, mc_u32 timeout_ms, struct http_meta *out_meta, int *out_is_html,
	const struct body_sink *html_sink, const struct body_sink *text_sink) {
	if (!argv0 || !u || !u->host || !u->path) return 1;
	if (u->scheme != URL_HTTPS) return 1;
	if (u->port == 0) return 1;

	// DNS server
	mc_u8 dns_server[16];
	int have_dns = net_resolv_conf_pick_v6(dns_server);
	if (!have_dns) {
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

	mc_i32 fd = -1;
	if (!tcp6_connect_timeout(argv0, host_ip6, u->port, timeout_ms, &fd)) {
		return 1;
	}

	// === TLS 1.3 handshake (no cert validation) ===
	mc_u8 ch_random[32];
	mc_u8 ch_sid[32];
	mc_u8 x25519_priv[32];
	mc_u8 x25519_pub[32];
	tls_getrandom_or_die(argv0, ch_random, sizeof(ch_random));
	tls_getrandom_or_die(argv0, ch_sid, sizeof(ch_sid));
	tls_getrandom_or_die(argv0, x25519_priv, sizeof(x25519_priv));
	mc_x25519_public(x25519_pub, x25519_priv);

	mc_u8 ch[2048];
	mc_usize ch_len = 0;
	if (mc_tls13_build_client_hello(host_tmp, mc_strlen(host_tmp), ch_random, ch_sid, sizeof(ch_sid), x25519_pub, ch, sizeof(ch), &ch_len) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	// Send ClientHello in a plaintext TLS record
	mc_u8 rec[5 + 2048];
	if (ch_len > 2048) {
		(void)mc_sys_close(fd);
		return 1;
	}
	rec[0] = 22;
	rec[1] = 0x03;
	rec[2] = 0x01;
	rec[3] = (mc_u8)((ch_len >> 8) & 0xFFu);
	rec[4] = (mc_u8)(ch_len & 0xFFu);
	mc_memcpy(rec + 5, ch, ch_len);
	if (mc_write_all(fd, rec, 5 + ch_len) < 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	// Read until ServerHello
	mc_u8 rhdr[5];
	mc_u8 payload[65536];
	mc_u8 sh_msg[2048];
	mc_usize sh_len = 0;
	int got_sh = 0;
	for (int iter = 0; iter < 32; iter++) {
		if (!tls_read_exact_timeout(fd, rhdr, 5, timeout_ms)) break;
		mc_u8 rtype = rhdr[0];
		mc_u16 rlen = (mc_u16)(((mc_u16)rhdr[3] << 8) | (mc_u16)rhdr[4]);
		if (rlen > sizeof(payload)) break;
		if (!tls_read_exact_timeout(fd, payload, (mc_usize)rlen, timeout_ms)) break;
		if (rtype != 22) continue;
		mc_usize off = 0;
		while (off + 4 <= (mc_usize)rlen) {
			mc_u8 ht = payload[off + 0];
			mc_u32 hl = ((mc_u32)payload[off + 1] << 16) | ((mc_u32)payload[off + 2] << 8) | (mc_u32)payload[off + 3];
			mc_usize htot = 4u + (mc_usize)hl;
			if (off + htot > (mc_usize)rlen) break;
			if (ht == MC_TLS13_HANDSHAKE_SERVER_HELLO) {
				if (htot > sizeof(sh_msg)) break;
				mc_memcpy(sh_msg, payload + off, htot);
				sh_len = htot;
				got_sh = 1;
				break;
			}
			off += htot;
		}
		if (got_sh) break;
	}
	if (!got_sh) {
		(void)mc_sys_close(fd);
		return 1;
	}

	struct mc_tls13_server_hello sh;
	if (mc_tls13_parse_server_hello(sh_msg, sh_len, &sh) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	struct mc_tls13_transcript t;
	mc_tls13_transcript_init(&t);
	mc_tls13_transcript_update(&t, ch, ch_len);
	mc_tls13_transcript_update(&t, sh_msg, sh_len);
	mc_u8 chsh_hash[32];
	mc_tls13_transcript_final(&t, chsh_hash);

	if (sh.key_share_group != MC_TLS13_GROUP_X25519 || sh.key_share_len != 32) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (sh.selected_version != 0x0304) {
		(void)mc_sys_close(fd);
		return 1;
	}

	mc_u8 ecdhe[32];
	if (mc_x25519_shared(ecdhe, x25519_priv, sh.key_share) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	mc_u8 zeros32[32];
	mc_memset(zeros32, 0, sizeof(zeros32));
	mc_u8 early[32];
	mc_hkdf_extract(zeros32, sizeof(zeros32), zeros32, sizeof(zeros32), early);

	mc_u8 derived[32];
	if (mc_tls13_derive_secret(early, "derived", sha256_empty32_ptr(), derived) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	mc_u8 handshake_secret[32];
	mc_hkdf_extract(derived, sizeof(derived), ecdhe, sizeof(ecdhe), handshake_secret);

	mc_u8 c_hs[32];
	mc_u8 s_hs[32];
	if (mc_tls13_derive_secret(handshake_secret, "c hs traffic", chsh_hash, c_hs) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_derive_secret(handshake_secret, "s hs traffic", chsh_hash, s_hs) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	mc_u8 c_key[16];
	mc_u8 c_iv[12];
	mc_u8 s_key[16];
	mc_u8 s_iv[12];
	if (mc_tls13_hkdf_expand_label(c_hs, "key", MC_NULL, 0, c_key, sizeof(c_key)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(c_hs, "iv", MC_NULL, 0, c_iv, sizeof(c_iv)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(s_hs, "key", MC_NULL, 0, s_key, sizeof(s_key)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(s_hs, "iv", MC_NULL, 0, s_iv, sizeof(s_iv)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	mc_u64 s_hs_seq = 0;
	mc_u64 c_hs_seq = 0;
	int verified_server_finished = 0;
	mc_u8 hs_buf[131072];
	mc_usize hs_buf_len = 0;
	mc_u8 th_post_server_finished[32];
	mc_u8 master_secret[32];
	int have_master = 0;
	int have_th_post_sf = 0;

	for (int iter = 0; iter < 2048; iter++) {
		mc_usize rlen = 0;
		if (!tls_record_read(fd, timeout_ms, rhdr, payload, sizeof(payload), &rlen)) break;
		mc_u8 rtype = rhdr[0];
		if (rtype == MC_TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
		if (rtype == MC_TLS_CONTENT_ALERT) break;
		if (rtype != MC_TLS_CONTENT_APPLICATION_DATA) continue;

		mc_u8 record[5 + 65536];
		mc_usize record_len = 5u + rlen;
		if (record_len > sizeof(record)) break;
		mc_memcpy(record, rhdr, 5);
		mc_memcpy(record + 5, payload, rlen);

		mc_u8 inner_type = 0;
		mc_u8 pt[65536];
		mc_usize pt_len = 0;
		if (mc_tls_record_decrypt(s_key, s_iv, s_hs_seq, record, record_len, &inner_type, pt, sizeof(pt), &pt_len) != 0) break;
		s_hs_seq++;
		if (inner_type != MC_TLS_CONTENT_HANDSHAKE) continue;
		if (tls_hs_append(hs_buf, sizeof(hs_buf), &hs_buf_len, pt, pt_len) != 0) break;

		for (;;) {
			mc_u8 msg_type = 0;
			mc_u32 msg_body_len = 0;
			mc_u8 msg[65536];
			mc_usize msg_len = 0;
			int cr = tls_hs_consume_one(hs_buf, &hs_buf_len, &msg_type, &msg_body_len, msg, sizeof(msg), &msg_len);
			if (cr == 1) break;
			if (cr != 0) {
				(void)mc_sys_close(fd);
				return 1;
			}

			if (msg_type == 20) {
				mc_u8 th_pre[32];
				mc_tls13_transcript_final(&t, th_pre);
				mc_u8 s_finished_key[32];
				if (mc_tls13_finished_key(s_hs, s_finished_key) != 0) {
					(void)mc_sys_close(fd);
					return 1;
				}
				mc_u8 expected_verify[32];
				mc_tls13_finished_verify_data(s_finished_key, th_pre, expected_verify);
				mc_memset(s_finished_key, 0, sizeof(s_finished_key));
				if (msg_body_len != 32 || msg_len != 36) {
					(void)mc_sys_close(fd);
					return 1;
				}
				if (mc_memcmp(msg + 4, expected_verify, 32) != 0) {
					(void)mc_sys_close(fd);
					return 1;
				}
				verified_server_finished = 1;
				mc_tls13_transcript_update(&t, msg, msg_len);
				mc_tls13_transcript_final(&t, th_post_server_finished);
				have_th_post_sf = 1;

				mc_u8 derived2[32];
				if (mc_tls13_derive_secret(handshake_secret, "derived", sha256_empty32_ptr(), derived2) != 0) {
					(void)mc_sys_close(fd);
					return 1;
				}
				mc_hkdf_extract(derived2, sizeof(derived2), zeros32, sizeof(zeros32), master_secret);
				have_master = 1;
				break;
			}

			mc_tls13_transcript_update(&t, msg, msg_len);
		}

		if (verified_server_finished) break;
	}

	if (!verified_server_finished || !have_master || !have_th_post_sf) {
		(void)mc_sys_close(fd);
		return 1;
	}

	// Send client Finished
	mc_u8 c_finished_key[32];
	if (mc_tls13_finished_key(c_hs, c_finished_key) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	mc_u8 client_verify[32];
	mc_tls13_finished_verify_data(c_finished_key, th_post_server_finished, client_verify);
	mc_memset(c_finished_key, 0, sizeof(c_finished_key));

	mc_u8 fin_msg[4 + 32];
	fin_msg[0] = 20;
	fin_msg[1] = 0;
	fin_msg[2] = 0;
	fin_msg[3] = 32;
	mc_memcpy(fin_msg + 4, client_verify, 32);

	mc_u8 enc_fin[5 + 256];
	mc_usize enc_fin_len = 0;
	if (mc_tls_record_encrypt(c_key, c_iv, c_hs_seq, MC_TLS_CONTENT_HANDSHAKE, fin_msg, sizeof(fin_msg), enc_fin, sizeof(enc_fin), &enc_fin_len) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	c_hs_seq++;
	if (mc_write_all(fd, enc_fin, enc_fin_len) < 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	// Derive application traffic keys (using transcript hash after ServerFinished)
	mc_tls13_transcript_update(&t, fin_msg, sizeof(fin_msg));
	mc_u8 c_ap_traffic[32];
	mc_u8 s_ap_traffic[32];
	if (mc_tls13_derive_secret(master_secret, "c ap traffic", th_post_server_finished, c_ap_traffic) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_derive_secret(master_secret, "s ap traffic", th_post_server_finished, s_ap_traffic) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	struct tls_stream ts;
	mc_memset(&ts, 0, sizeof(ts));
	ts.fd = fd;
	ts.timeout_ms = timeout_ms;
	if (mc_tls13_hkdf_expand_label(c_ap_traffic, "key", MC_NULL, 0, ts.c_ap_key, sizeof(ts.c_ap_key)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(c_ap_traffic, "iv", MC_NULL, 0, ts.c_ap_iv, sizeof(ts.c_ap_iv)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(s_ap_traffic, "key", MC_NULL, 0, ts.s_ap_key, sizeof(ts.s_ap_key)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_hkdf_expand_label(s_ap_traffic, "iv", MC_NULL, 0, ts.s_ap_iv, sizeof(ts.s_ap_iv)) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	ts.c_ap_seq = 0;
	ts.s_ap_seq = 0;
	ts.off = 0;
	ts.have = 0;

	// Send HTTP request as application data
	char req[4096];
	mc_usize req_len = 0;
	{
		static const char p0[] = "GET ";
		static const char p1[] = " HTTP/1.1\r\nHost: ";
		static const char p2[] = "\r\nUser-Agent: monacc-browse\r\nConnection: close\r\n\r\n";
		mc_usize l0 = sizeof(p0) - 1u;
		mc_usize l1 = sizeof(p1) - 1u;
		mc_usize l2 = sizeof(p2) - 1u;
		mc_usize path_len = mc_strlen(u->path);
		mc_usize host_len = mc_strlen(host_tmp);
		mc_usize need = l0 + path_len + l1 + host_len + l2;
		if (need > sizeof(req)) {
			(void)mc_sys_close(fd);
			return 1;
		}
		mc_memcpy(req + req_len, p0, l0);
		req_len += l0;
		mc_memcpy(req + req_len, u->path, path_len);
		req_len += path_len;
		mc_memcpy(req + req_len, p1, l1);
		req_len += l1;
		mc_memcpy(req + req_len, host_tmp, host_len);
		req_len += host_len;
		mc_memcpy(req + req_len, p2, l2);
		req_len += l2;
	}

	mc_u8 req_record[5 + 4096 + 64];
	mc_usize req_record_len = 0;
	if (mc_tls_record_encrypt(ts.c_ap_key, ts.c_ap_iv, ts.c_ap_seq, MC_TLS_CONTENT_APPLICATION_DATA, (const mc_u8 *)req, req_len,
		req_record, sizeof(req_record), &req_record_len) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	ts.c_ap_seq++;
	if (mc_write_all(fd, req_record, req_record_len) < 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	// Parse headers over decrypted stream
	mc_u8 buf[NET_IOBUF_CAP];
	mc_usize have = 0;
	mc_usize off = 0;
	struct http_meta meta;
	if (!parse_http_headers_tls(argv0, &ts, &meta, buf, &have, &off)) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (out_meta) *out_meta = meta;
	int is_html = http_content_type_is_html(meta.content_type);
	if (out_is_html) *out_is_html = is_html;

	if (meta.status == 301 || meta.status == 302 || meta.status == 303 || meta.status == 307 || meta.status == 308) {
		(void)mc_sys_close(fd);
		return 0;
	}
	if (meta.status < 200 || meta.status >= 300) {
		(void)mc_sys_close(fd);
		return 1;
	}

	const struct body_sink *sink = is_html ? html_sink : text_sink;
	int rc = http_stream_body_tls(argv0, &ts, &meta, buf, &have, &off, sink);
	(void)mc_sys_close(fd);
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

static void html_finish(struct html *h, const struct url *base_for_links) {
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
		char abs[4096];
		if (base_for_links && resolve_url_against(base_for_links, h->links.href[i], abs, sizeof(abs))) {
			out_cstr(&h->out, abs);
		} else {
			out_cstr(&h->out, h->links.href[i]);
		}
		out_byte(&h->out, '\n');
	}
	out_flush(&h->out);
}

static int render_html_fd(mc_i32 fd, int emit_text, const struct url *base_for_links) {
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

	html_finish(&h, base_for_links);
	return 0;
}

static MC_NORETURN void browse_usage(const char *argv0) {
	mc_die_usage(argv0,
		"browse URL\n"
		"browse -dump-links URL\n"
		"browse --render-html FILE|-\n"
		"browse --render-html-base BASE_URL FILE|-\n"
		"browse --parse-url URL\n"
		"browse --resolve-url BASE_URL HREF\n"
		"browse --parse-http-headers  < headers.txt\n"
		"browse --decode-chunked      < chunked.txt\n"
		"\n"
		"WP1/WP2:\n"
		"  --render-html: offline HTML->text rendering\n"
		"  URL fetch: http:// and https:// (no certificate validation)\n"
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
	mc_u8 buf[NET_IOBUF_CAP];
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

static int cmd_resolve_url(const char *argv0, const char *base_s, const char *href) {
	struct url b;
	if (!parse_url_small(base_s, &b)) browse_usage(argv0);
	char out[4096];
	if (!resolve_url_against(&b, href, out, sizeof(out))) {
		mc_write_str(1, "-\n");
		return 0;
	}
	mc_write_str(1, out);
	mc_write_str(1, "\n");
	return 0;
}

static int cmd_decode_chunked(const char *argv0) {
	mc_u8 buf[NET_IOBUF_CAP];
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
	struct http_meta meta;
	mc_u32 timeout_ms = 5000;
	int is_html = 1;
	int rc = 0;

	// WP3: redirects (max depth 5)
	for (int depth = 0; depth < 5; depth++) {
		if (dump_links_only) {
			struct html h;
			html_init(&h);
			h.emit_text = 0;
			struct body_sink html_sink;
			html_sink.kind = SINK_HTML;
			html_sink.ctx = &h;
			struct body_sink text_sink;
			text_sink.kind = SINK_DISCARD;
			text_sink.ctx = 0;

			rc = (u.scheme == URL_HTTPS)
				? https_fetch(argv0, &u, timeout_ms, &meta, &is_html, &html_sink, &text_sink)
				: http_fetch(argv0, &u, timeout_ms, &meta, &is_html, &html_sink, &text_sink);
			if (rc != 0) return rc;

			if (meta.status == 301 || meta.status == 302 || meta.status == 303 || meta.status == 307 || meta.status == 308) {
				if (meta.location[0]) {
					char next[4096];
					if (resolve_url_against(&u, meta.location, next, sizeof(next))) {
						if (!parse_url_small(next, &u)) return 1;
						continue;
					}
				}
				return 1;
			}

			if (!is_html) {
				mc_write_str(1, "Links:\n");
				return 0;
			}
			html_finish(&h, &u);
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

		rc = (u.scheme == URL_HTTPS)
			? https_fetch(argv0, &u, timeout_ms, &meta, &is_html, &html_sink, &text_sink)
			: http_fetch(argv0, &u, timeout_ms, &meta, &is_html, &html_sink, &text_sink);
		if (rc != 0) return rc;

		if (meta.status == 301 || meta.status == 302 || meta.status == 303 || meta.status == 307 || meta.status == 308) {
			if (meta.location[0]) {
				char next[4096];
				if (resolve_url_against(&u, meta.location, next, sizeof(next))) {
					if (!parse_url_small(next, &u)) return 1;
					continue;
				}
			}
			return 1;
		}

		if (is_html) {
			html_finish(&h, &u);
			return 0;
		}
		mc_write_str(1, "\n\nLinks:\n");
		return 0;
	}
	return 1;

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
			html_finish(&h, &u);
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
		html_finish(&h, &u);
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
			return render_html_fd(0, 1, 0);
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		int rc = render_html_fd((mc_i32)fd, 1, 0);
		(void)mc_sys_close((mc_i32)fd);
		return rc;
	}

	if (mc_streq(argv[1], "--render-html-base")) {
		if (argc != 4 || !argv[2] || !argv[3]) browse_usage(argv0);
		struct url base;
		if (!parse_url_small(argv[2], &base)) browse_usage(argv0);
		const char *path = argv[3];
		if (mc_streq(path, "-")) {
			return render_html_fd(0, 1, &base);
		}
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd < 0) mc_die_errno(argv0, path, fd);
		int rc = render_html_fd((mc_i32)fd, 1, &base);
		(void)mc_sys_close((mc_i32)fd);
		return rc;
	}

	if (mc_streq(argv[1], "--parse-url")) {
		if (argc != 3 || !argv[2]) browse_usage(argv0);
		return cmd_parse_url(argv0, argv[2]);
	}

	if (mc_streq(argv[1], "--resolve-url")) {
		if (argc != 4 || !argv[2] || !argv[3]) browse_usage(argv0);
		return cmd_resolve_url(argv0, argv[2], argv[3]);
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

	// WP2/WP4: fetch URL
	if (argc == 2 && argv[1] && argv[1][0] != '-') {
		return cmd_fetch_and_render(argv0, argv[1], 0);
	}

	// Unknown mode
	browse_usage(argv0);
	return 2;
}
