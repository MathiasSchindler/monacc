#include "mc.h"
#include "mc_net.h"

static mc_u16 mc_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u16 mc_htons(mc_u16 x) {
	return mc_bswap16(x);
}

static mc_u16 mc_ntohs(mc_u16 x) {
	return mc_bswap16(x);
}

static int mc_hexval(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (int)(c - (mc_u8)'0');
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return 10 + (int)(c - (mc_u8)'a');
	if (c >= (mc_u8)'A' && c <= (mc_u8)'F') return 10 + (int)(c - (mc_u8)'A');
	return -1;
}

// Strict IPv6 literal parser.
// Supports :: compression. No IPv4-embedded form. No zone index (%eth0).
static int parse_ipv6_literal(const char *s, mc_u8 out[16]) {
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
			int hv = mc_hexval((mc_u8)*p);
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

static int resolv_conf_pick_v6(mc_u8 out_server[16]) {
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
		if (parse_ipv6_literal(tmp, out_server)) {
			return 1;
		}
	}

	return 0;
}

static mc_u16 dns_pick_id(void) {
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

static int dns_encode_qname(mc_u8 *dst, mc_usize cap, const char *name, mc_usize *io_off) {
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

static int dns_name_skip(const mc_u8 *msg, mc_usize msglen, mc_usize off, mc_usize *out_off) {
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

static int dns6_resolve_first_aaaa(const char *argv0, const mc_u8 server_ip[16], mc_u16 server_port, const char *name, mc_u32 timeout_ms,
	mc_u8 out_ip[16]) {
	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = mc_htons(server_port);
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
		mc_u16 id = dns_pick_id();
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

		if (!dns_encode_qname(q, sizeof(q), name, &qn)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		if (qn + 4 > sizeof(q)) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}
		mc_u16 qt = mc_htons(28);
		mc_u16 qc = mc_htons(1);
		q[qn++] = (mc_u8)(qt >> 8);
		q[qn++] = (mc_u8)(qt & 0xFFu);
		q[qn++] = (mc_u8)(qc >> 8);
		q[qn++] = (mc_u8)(qc & 0xFFu);

		mc_u8 tcpbuf[2 + sizeof(q)];
		const void *sendbuf = q;
		mc_usize sendlen = qn;
		if (use_tcp) {
			mc_u16 l = mc_htons((mc_u16)qn);
			tcpbuf[0] = (mc_u8)(l >> 8);
			tcpbuf[1] = (mc_u8)(l & 0xFFu);
			for (mc_usize i = 0; i < qn; i++) tcpbuf[2 + i] = q[i];
			sendbuf = tcpbuf;
			sendlen = 2 + qn;
		}

		r = mc_sys_sendto((mc_i32)fd, sendbuf, sendlen, 0, 0, 0);
		if (r < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 0;
		}

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

		mc_u8 ans[1536];
		mc_i64 nr = mc_sys_recvfrom((mc_i32)fd, ans, sizeof(ans), 0, 0, 0);
		(void)mc_sys_close((mc_i32)fd);
		if (nr < 0 || nr < 12) return 0;
		mc_usize msglen = (mc_usize)nr;
		mc_u16 rid = (mc_u16)(((mc_u16)ans[0] << 8) | (mc_u16)ans[1]);
		if (rid != id) return 0;
		mc_u16 flags = (mc_u16)(((mc_u16)ans[2] << 8) | (mc_u16)ans[3]);
		int tc = (flags & 0x0200u) ? 1 : 0;
		int rcode = (int)(flags & 0x000Fu);
		if ((flags & 0x8000u) == 0 || rcode != 0) return 0;

		mc_u16 qd = (mc_u16)(((mc_u16)ans[4] << 8) | (mc_u16)ans[5]);
		mc_u16 an = (mc_u16)(((mc_u16)ans[6] << 8) | (mc_u16)ans[7]);

		mc_usize off = 12;
		for (mc_u16 qi = 0; qi < qd; qi++) {
			mc_usize noff;
			if (!dns_name_skip(ans, msglen, off, &noff)) return 0;
			off = noff;
			if (off + 4 > msglen) return 0;
			off += 4;
		}

		for (mc_u16 ai = 0; ai < an; ai++) {
			mc_usize noff;
			if (!dns_name_skip(ans, msglen, off, &noff)) return 0;
			off = noff;
			if (off + 10 > msglen) return 0;
			mc_u16 atype = mc_ntohs((mc_u16)(((mc_u16)ans[off] << 8) | (mc_u16)ans[off + 1]));
			mc_u16 rdlen = mc_ntohs((mc_u16)(((mc_u16)ans[off + 8] << 8) | (mc_u16)ans[off + 9]));
			off += 10;
			if (off + rdlen > msglen) return 0;
			if (atype == 28 && rdlen == 16) {
				for (int k = 0; k < 16; k++) out_ip[k] = ans[off + (mc_usize)k];
				return 1;
			}
			off += rdlen;
		}

		if (!use_tcp && tc) {
			continue;
		}
	}

	return 0;
}

static MC_NORETURN void wget6_usage(const char *argv0) {
	mc_die_usage(argv0, "wget6 [-O FILE] [-s DNS_SERVER] [-W TIMEOUT_MS] URL|HOST[/PATH]");
}

static int is_alpha(char c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// Parse very small URL subset:
// - Optional scheme "http://"
// - Host is either:
//   - bracketed IPv6 literal: http://[::1]/path
//   - hostname: http://example.com/path
// - Optional :port
// - Path defaults to "/"
static int parse_http_url(const char *in, const char **out_host, mc_usize *out_host_len, mc_u16 *out_port, const char **out_path) {
	const char *p = in;
	// scheme?
	const char *s = p;
	while (*p && is_alpha(*p)) p++;
	if (*p == ':' && p[1] == '/' && p[2] == '/') {
		// Only support http
		mc_usize slen = (mc_usize)(p - s);
		if (slen != 4 || !(s[0] == 'h' || s[0] == 'H') || !(s[1] == 't' || s[1] == 'T') || !(s[2] == 't' || s[2] == 'T') ||
			!(s[3] == 'p' || s[3] == 'P')) {
			return 0;
		}
		p += 3;
	} else {
		p = in;
	}

	if (*p == 0) return 0;

	*out_port = 80;

	if (*p == '[') {
		p++;
		const char *h0 = p;
		while (*p && *p != ']') p++;
		if (*p != ']') return 0;
		*out_host = h0;
		*out_host_len = (mc_usize)(p - h0);
		p++;
	} else {
		const char *h0 = p;
		while (*p && *p != '/' && *p != ':') p++;
		*out_host = h0;
		*out_host_len = (mc_usize)(p - h0);
	}
	if (*out_host_len == 0) return 0;

	if (*p == ':') {
		p++;
		mc_u32 v = 0;
		const char *q = p;
		if (mc_parse_u32_dec_prefix(&q, &v) != 0) return 0;
		if (v == 0 || v > 65535u) return 0;
		*out_port = (mc_u16)v;
		p = q;
	}

	if (*p == 0) {
		*out_path = "/";
		return 1;
	}
	if (*p != '/') return 0;
	*out_path = p;
	return 1;
}

static mc_i64 write_all_or_die(const char *argv0, mc_i32 fd, const void *buf, mc_usize len) {
	mc_i64 r = mc_write_all(fd, buf, len);
	if (r < 0) mc_die_errno(argv0, "write", r);
	return r;
}

static int starts_with_ci(const char *s, const char *pre) {
	mc_usize i = 0;
	while (pre[i]) {
		char a = s[i];
		char b = pre[i];
		if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
		if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
		if (a != b) return 0;
		i++;
	}
	return 1;
}

static mc_i64 read_line(mc_i32 fd, char *line, mc_usize cap, mc_u8 *buf, mc_usize *io_have, mc_usize *io_off) {
	mc_usize n = 0;
	for (;;) {
		// scan existing buffer for \n
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

		// need more data
		if (*io_off > 0) {
			mc_usize rem = *io_have - *io_off;
			for (mc_usize k = 0; k < rem; k++) buf[k] = buf[*io_off + k];
			*io_have = rem;
			*io_off = 0;
		}
		mc_i64 r = mc_sys_read(fd, buf + *io_have, 4096 - *io_have);
		if (r < 0) return r;
		if (r == 0) {
			// EOF
			if (n == 0) return 0;
			return (mc_i64)-MC_EINVAL;
		}
		*io_have += (mc_usize)r;
	}
}

static int wget6_fetch_once(const char *argv0, const char *host, mc_usize host_len, const mc_u8 ip6[16], mc_u16 port, const char *path,
	mc_u32 timeout_ms, mc_i32 outfd, int follow_redirects, int depth) {
	(void)follow_redirects;
	(void)depth;

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = mc_htons(port);
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = ip6[k];

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
	write_all_or_die(argv0, (mc_i32)fd, "GET ", 4);
	write_all_or_die(argv0, (mc_i32)fd, path, mc_strlen(path));
	write_all_or_die(argv0, (mc_i32)fd, " HTTP/1.1\r\nHost: ", 17);
	write_all_or_die(argv0, (mc_i32)fd, host, host_len);
	write_all_or_die(argv0, (mc_i32)fd, "\r\nUser-Agent: monacc-wget6\r\nConnection: close\r\n\r\n", 62);

	// Read response headers
	mc_u8 buf[4096];
	mc_usize have = 0;
	mc_usize off = 0;
	char line[1024];

	mc_i64 nline = read_line((mc_i32)fd, line, sizeof(line), buf, &have, &off);
	if (nline <= 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}
	// Basic status parse: "HTTP/1.1 200"
	int status = 0;
	const char *sp = line;
	while (*sp && *sp != ' ') sp++;
	while (*sp == ' ') sp++;
	mc_i32 st = 0;
	if (mc_parse_i32_dec(sp, &st) != 0) st = 0;
	status = (int)st;

	mc_i64 content_len = -1;
	int chunked = 0;
	// headers
	for (;;) {
		nline = read_line((mc_i32)fd, line, sizeof(line), buf, &have, &off);
		if (nline < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
		if (nline == 0) break;

		if (starts_with_ci(line, "content-length:")) {
			const char *p = line + 15;
			while (*p == ' ' || *p == '\t') p++;
			mc_i64 v = 0;
			if (mc_parse_i64_dec(p, &v) == 0 && v >= 0) content_len = v;
		}
		if (starts_with_ci(line, "transfer-encoding:")) {
			const char *p = line + 18;
			while (*p == ' ' || *p == '\t') p++;
			if (starts_with_ci(p, "chunked")) chunked = 1;
		}
	}

	if (status < 200 || status >= 300) {
		// Still drain body to be polite? for now just fail.
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	// Body
	if (!chunked) {
		// first write any buffered bytes
		if (off < have) {
			mc_usize n = have - off;
			mc_i64 wr = mc_write_all(outfd, buf + off, n);
			if (wr < 0) mc_die_errno(argv0, "write", wr);
			off = have;
		}

		mc_i64 remaining = content_len;
		for (;;) {
			mc_i64 nr = mc_sys_read((mc_i32)fd, buf, sizeof(buf));
			if (nr < 0) mc_die_errno(argv0, "read", nr);
			if (nr == 0) break;
			mc_usize wn = (mc_usize)nr;
			if (remaining >= 0 && (mc_i64)wn > remaining) wn = (mc_usize)remaining;
			mc_i64 wr = mc_write_all(outfd, buf, wn);
			if (wr < 0) mc_die_errno(argv0, "write", wr);
			if (remaining >= 0) {
				remaining -= (mc_i64)wn;
				if (remaining <= 0) break;
			}
		}
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	// Chunked decoding (minimal)
	for (;;) {
		// chunk size line
		nline = read_line((mc_i32)fd, line, sizeof(line), buf, &have, &off);
		if (nline < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
		if (nline == 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
		// parse hex until ';' or end
		mc_u64 sz = 0;
		const char *p = line;
		while (*p && *p != ';') {
			int hv = mc_hexval((mc_u8)*p);
			if (hv < 0) break;
			sz = (sz << 4) | (mc_u64)hv;
			p++;
			if (sz > (mc_u64)(1024u * 1024u * 1024u)) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
		}
		if (sz == 0) {
			// trailer headers until blank
			for (;;) {
				nline = read_line((mc_i32)fd, line, sizeof(line), buf, &have, &off);
				if (nline <= 0) break;
			}
			break;
		}

		mc_u64 left = sz;
		// write from buffered region first
		while (left > 0) {
			if (off < have) {
				mc_usize avail = have - off;
				mc_usize take = avail;
				if ((mc_u64)take > left) take = (mc_usize)left;
				mc_i64 wr = mc_write_all(outfd, buf + off, take);
				if (wr < 0) mc_die_errno(argv0, "write", wr);
				off += take;
				left -= (mc_u64)take;
				continue;
			}
			mc_i64 nr = mc_sys_read((mc_i32)fd, buf, sizeof(buf));
			if (nr < 0) mc_die_errno(argv0, "read", nr);
			if (nr == 0) {
				(void)mc_sys_close((mc_i32)fd);
				return 1;
			}
			have = (mc_usize)nr;
			off = 0;
		}

		// Consume CRLF after chunk
		char crlf[8];
		nline = read_line((mc_i32)fd, crlf, sizeof(crlf), buf, &have, &off);
		if (nline < 0) {
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
	}

	(void)mc_sys_close((mc_i32)fd);
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "wget6";

	const char *out_path = 0;
	mc_u32 timeout_ms = 5000;
	mc_u8 dns_server[16];
	int have_dns_server = 0;
	int follow_redirects = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-O")) {
			i++;
			if (i >= argc) wget6_usage(argv0);
			out_path = argv[i];
			continue;
		}
		if (mc_streq(a, "-s")) {
			i++;
			if (i >= argc) wget6_usage(argv0);
			if (!parse_ipv6_literal(argv[i], dns_server)) wget6_usage(argv0);
			have_dns_server = 1;
			continue;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) wget6_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) wget6_usage(argv0);
			timeout_ms = v;
			continue;
		}
		if (mc_streq(a, "-L")) {
			follow_redirects = 1;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) wget6_usage(argv0);
		break;
	}

	if (i + 1 != argc) wget6_usage(argv0);
	const char *url = argv[i];

	const char *host = 0;
	mc_usize host_len = 0;
	mc_u16 port = 0;
	const char *path = 0;
	if (!parse_http_url(url, &host, &host_len, &port, &path)) {
		wget6_usage(argv0);
	}

	// copy host into a 0-terminated buffer
	if (host_len >= 256) wget6_usage(argv0);
	char host0[256];
	for (mc_usize k = 0; k < host_len; k++) host0[k] = host[k];
	host0[host_len] = 0;

	mc_u8 ip6[16];
	if (!parse_ipv6_literal(host0, ip6)) {
		int default_google = 0;
		if (!have_dns_server) {
			if (!resolv_conf_pick_v6(dns_server)) {
				(void)parse_ipv6_literal("2001:4860:4860::8888", dns_server);
				default_google = 1;
			}
			have_dns_server = 1;
		}
		if (!dns6_resolve_first_aaaa(argv0, dns_server, 53, host0, timeout_ms, ip6)) {
			if (default_google) {
				mc_u8 dns2[16];
				(void)parse_ipv6_literal("2001:4860:4860::8844", dns2);
				if (dns6_resolve_first_aaaa(argv0, dns2, 53, host0, timeout_ms, ip6)) {
					goto resolved_ok;
				}
			}
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": resolve failed\n");
			return 1;
		}
	}

resolved_ok:;

	mc_i32 outfd = 1;
	if (out_path) {
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, out_path, MC_O_WRONLY | MC_O_CREAT | MC_O_TRUNC | MC_O_CLOEXEC, 0644);
		if (fd < 0) mc_die_errno(argv0, out_path, fd);
		outfd = (mc_i32)fd;
	}

	int rc = wget6_fetch_once(argv0, host0, host_len, ip6, port, path, timeout_ms, outfd, follow_redirects, 0);

	if (out_path) {
		(void)mc_sys_close(outfd);
	}
	return rc;
}
