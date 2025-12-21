#include "masto_dns.h"

static int is_hex(mc_u8 c) {
	return (c >= (mc_u8)'0' && c <= (mc_u8)'9') || (c >= (mc_u8)'a' && c <= (mc_u8)'f') || (c >= (mc_u8)'A' && c <= (mc_u8)'F');
}

static mc_u8 hex_val(mc_u8 c) {
	if (c >= (mc_u8)'0' && c <= (mc_u8)'9') return (mc_u8)(c - (mc_u8)'0');
	if (c >= (mc_u8)'a' && c <= (mc_u8)'f') return (mc_u8)(10 + (c - (mc_u8)'a'));
	return (mc_u8)(10 + (c - (mc_u8)'A'));
}

static int parse_group_u16(const char *p, mc_usize n, mc_u16 *out) {
	if (!out) return -1;
	if (n == 0 || n > 4) return -1;
	mc_u16 v = 0;
	for (mc_usize i = 0; i < n; i++) {
		mc_u8 c = (mc_u8)p[i];
		if (!is_hex(c)) return -1;
		v = (mc_u16)((v << 4) | (mc_u16)hex_val(c));
	}
	*out = v;
	return 0;
}

static int parse_side(const char *start, const char *end, mc_u16 *words, int *io_n) {
	// Parse groups separated by ':' from start..end (end exclusive).
	int n = *io_n;
	const char *p = start;
	if (p == end) return 0;
	while (p < end) {
		const char *q = p;
		while (q < end && *q != ':') q++;
		if (n >= 8) return -1;
		mc_u16 v = 0;
		if (parse_group_u16(p, (mc_usize)(q - p), &v) != 0) return -1;
		words[n++] = v;
		p = q;
		if (p < end) {
			// skip ':'
			p++;
			if (p == end) return -1;
		}
	}
	*io_n = n;
	return 0;
}

static int masto_parse_ipv6(const char *s, struct mc_in6_addr *out) {
	// Minimal inet_pton(AF_INET6) equivalent.
	// Supports :: compression and 1-4 hex digits per group.
	if (!s || !out) return -1;

	const char *start = s;
	const char *end = s + mc_strlen(s);
	if (*start == '[') {
		start++;
		const char *rb = mc_strchr(start, ']');
		if (!rb) return -1;
		end = rb;
	}

	// Find "::" (at most one).
	const char *dbl = MC_NULL;
	for (const char *p = start; p + 1 < end; p++) {
		if (p[0] == ':' && p[1] == ':') {
			dbl = p;
			break;
		}
	}

	mc_u16 words[8];
	for (int i = 0; i < 8; i++) words[i] = 0;

	if (!dbl) {
		int n = 0;
		if (parse_side(start, end, words, &n) != 0) return -1;
		if (n != 8) return -1;
	} else {
		int left_n = 0;
		if (parse_side(start, dbl, words, &left_n) != 0) return -1;

		// Parse right side into a temporary list.
		mc_u16 right[8];
		int right_n = 0;
		if (parse_side(dbl + 2, end, right, &right_n) != 0) return -1;
		if (left_n + right_n > 8) return -1;

		// Copy right side to the end.
		for (int i = 0; i < right_n; i++) {
			words[8 - right_n + i] = right[i];
		}
		// Middle is already zero.
	}

	for (int i = 0; i < 8; i++) {
		out->s6_addr[i * 2 + 0] = (mc_u8)(words[i] >> 8);
		out->s6_addr[i * 2 + 1] = (mc_u8)(words[i] >> 0);
	}
	return 0;
}

static mc_u16 masto_htons(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static int resolv_conf_pick_v6(struct mc_in6_addr *out_server) {
	if (!out_server) return 0;

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/etc/resolv.conf", MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) return 0;

	char buf[4096];
	mc_i64 n = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1u);
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
		mc_usize kwlen = mc_strlen(kw);
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

		// We only support IPv6 resolvers in this environment.
		if (masto_parse_ipv6(tmp, out_server) == 0) return 1;
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
	if (!dst || !name || !io_off) return 0;
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
		if (off + 1u + len >= cap) return 0;
		dst[off++] = (mc_u8)len;
		for (mc_usize i = 0; i < len; i++) dst[off++] = (mc_u8)label[i];
		if (*p == '.') p++;
	}
	if (off + 1u > cap) return 0;
	dst[off++] = 0;
	*io_off = off;
	return 1;
}

static int dns_name_skip(const mc_u8 *msg, mc_usize msglen, mc_usize off, mc_usize *out_off) {
	if (!msg || !out_off) return 0;
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

static int poll_in(mc_i32 fd, mc_u32 timeout_ms) {
	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = MC_POLLIN;
	pfd.revents = 0;
	mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
	if (pr <= 0) return 0;
	if ((pfd.revents & MC_POLLIN) == 0) return 0;
	return 1;
}

static int read_exact_timeout(mc_i32 fd, void *buf, mc_usize len, mc_u32 timeout_ms) {
	mc_u8 *p = (mc_u8 *)buf;
	mc_usize got = 0;
	while (got < len) {
		if (!poll_in(fd, timeout_ms)) return 0;
		mc_i64 r = mc_sys_read(fd, p + got, len - got);
		if (r < 0) return 0;
		if (r == 0) return 0;
		got += (mc_usize)r;
	}
	return 1;
}

static int dns_resolve_first_aaaa(
	const struct mc_in6_addr *server_ip,
	mc_u16 server_port,
	const char *name,
	mc_u32 timeout_ms,
	struct mc_in6_addr *out_ip
) {
	if (!server_ip || !name || !*name || !out_ip) return 0;

	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = masto_htons(server_port);
	sa.sin6_addr = *server_ip;

	for (int attempt = 0; attempt < 2; attempt++) {
		int use_tcp = (attempt == 1);
		mc_i32 stype = use_tcp ? MC_SOCK_STREAM : MC_SOCK_DGRAM;
		mc_i32 proto = use_tcp ? MC_IPPROTO_TCP : MC_IPPROTO_UDP;

		mc_i64 fd64 = mc_sys_socket(MC_AF_INET6, stype | MC_SOCK_CLOEXEC, proto);
		if (fd64 < 0) return 0;
		mc_i32 fd = (mc_i32)fd64;

		mc_i64 r = mc_sys_connect(fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) {
			(void)mc_sys_close(fd);
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
			(void)mc_sys_close(fd);
			return 0;
		}
		if (qn + 4u > sizeof(q)) {
			(void)mc_sys_close(fd);
			return 0;
		}
		q[qn++] = 0x00;
		q[qn++] = 0x1c; // AAAA
		q[qn++] = 0x00;
		q[qn++] = 0x01; // IN

		mc_u8 tcpbuf[2 + sizeof(q)];
		const void *sendbuf = q;
		mc_usize sendlen = qn;
		if (use_tcp) {
			tcpbuf[0] = (mc_u8)((qn >> 8) & 0xFFu);
			tcpbuf[1] = (mc_u8)(qn & 0xFFu);
			for (mc_usize i = 0; i < qn; i++) tcpbuf[2 + i] = q[i];
			sendbuf = tcpbuf;
			sendlen = 2u + qn;
		}

		r = mc_write_all(fd, sendbuf, sendlen);
		if (r < 0) {
			(void)mc_sys_close(fd);
			return 0;
		}

		mc_u8 resp[1024];
		mc_usize rn = 0;
		if (use_tcp) {
			if (!poll_in(fd, timeout_ms)) {
				(void)mc_sys_close(fd);
				return 0;
			}
			mc_u8 len2[2];
			if (!read_exact_timeout(fd, len2, 2u, timeout_ms)) {
				(void)mc_sys_close(fd);
				return 0;
			}
			mc_u16 mlen = (mc_u16)(((mc_u16)len2[0] << 8) | (mc_u16)len2[1]);
			if (mlen > sizeof(resp)) {
				(void)mc_sys_close(fd);
				return 0;
			}
			if (!read_exact_timeout(fd, resp, (mc_usize)mlen, timeout_ms)) {
				(void)mc_sys_close(fd);
				return 0;
			}
			rn = (mc_usize)mlen;
		} else {
			if (!poll_in(fd, timeout_ms)) {
				(void)mc_sys_close(fd);
				return 0;
			}
			mc_i64 rr = mc_sys_read(fd, resp, sizeof(resp));
			if (rr <= 0) {
				(void)mc_sys_close(fd);
				return 0;
			}
			rn = (mc_usize)rr;
		}

		(void)mc_sys_close(fd);

		if (rn < 12u) return 0;
		if (resp[0] != (mc_u8)(id >> 8) || resp[1] != (mc_u8)(id & 0xFFu)) return 0;
		mc_u16 flags = (mc_u16)(((mc_u16)resp[2] << 8) | (mc_u16)resp[3]);
		if ((flags & 0x8000u) == 0) return 0;
		mc_u16 qd = (mc_u16)(((mc_u16)resp[4] << 8) | (mc_u16)resp[5]);
		mc_u16 an = (mc_u16)(((mc_u16)resp[6] << 8) | (mc_u16)resp[7]);
		if (qd != 1 || an == 0) return 0;

		mc_usize off = 12;
		mc_usize noff = 0;
		if (!dns_name_skip(resp, rn, off, &noff)) return 0;
		off = noff;
		if (off + 4u > rn) return 0;
		off += 4u; // qtype+qclass

		for (mc_u16 i = 0; i < an; i++) {
			if (!dns_name_skip(resp, rn, off, &noff)) return 0;
			off = noff;
			if (off + 10u > rn) return 0;
			mc_u16 atype = (mc_u16)(((mc_u16)resp[off] << 8) | (mc_u16)resp[off + 1u]);
			mc_u16 aclass = (mc_u16)(((mc_u16)resp[off + 2u] << 8) | (mc_u16)resp[off + 3u]);
			mc_u16 rdlen = (mc_u16)(((mc_u16)resp[off + 8u] << 8) | (mc_u16)resp[off + 9u]);
			off += 10u;
			if (off + rdlen > rn) return 0;
			if (atype == 0x001cu && aclass == 0x0001u && rdlen == 16u) {
				mc_memcpy(out_ip->s6_addr, resp + off, 16u);
				return 1;
			}
			off += rdlen;
		}
		return 0;
	}

	return 0;
}

int masto_resolve_aaaa(const char *host, struct mc_in6_addr *out) {
	if (!host || !*host || !out) return -1;

	// IPv6 literal?
	for (const char *p = host; *p; p++) {
		if (*p == ':') {
			return masto_parse_ipv6(host, out);
		}
	}

	struct mc_in6_addr dns_server;
	int have = resolv_conf_pick_v6(&dns_server);
	if (!have) {
		(void)masto_parse_ipv6("2001:4860:4860::8888", &dns_server);
	}
	if (dns_resolve_first_aaaa(&dns_server, 53, host, 5000, out)) return 0;

	struct mc_in6_addr dns2;
	(void)masto_parse_ipv6("2001:4860:4860::8844", &dns2);
	if (dns_resolve_first_aaaa(&dns2, 53, host, 5000, out)) return 0;
	return -1;
}

mc_i64 masto_tcp_connect_v6(const struct mc_in6_addr *addr, mc_u16 port, mc_i32 timeout_ms) {
	if (!addr) return (mc_i64)-MC_EINVAL;

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC | MC_SOCK_NONBLOCK, MC_IPPROTO_TCP);
	if (fd < 0) return fd;

	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = masto_htons(port);
	sa.sin6_addr = *addr;

	mc_i64 rc = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
	if (rc == 0) {
		// Connected immediately.
		goto make_blocking;
	}
	if (rc != (mc_i64)-MC_EINPROGRESS) {
		mc_sys_close((mc_i32)fd);
		return rc;
	}

	struct mc_pollfd pfd;
	pfd.fd = (mc_i32)fd;
	pfd.events = MC_POLLOUT;
	pfd.revents = 0;

	rc = mc_sys_poll(&pfd, 1, timeout_ms);
	if (rc < 0) {
		mc_sys_close((mc_i32)fd);
		return rc;
	}
	if (rc == 0) {
		mc_sys_close((mc_i32)fd);
		return (mc_i64)-MC_ETIMEDOUT;
	}

	mc_i32 soerr = 0;
	mc_u32 slen = (mc_u32)sizeof(soerr);
	rc = mc_sys_getsockopt((mc_i32)fd, MC_SOL_SOCKET, MC_SO_ERROR, &soerr, &slen);
	if (rc < 0) {
		mc_sys_close((mc_i32)fd);
		return rc;
	}
	if (soerr != 0) {
		mc_sys_close((mc_i32)fd);
		return (mc_i64)-soerr;
	}

make_blocking:
	// Clear O_NONBLOCK.
	mc_i64 fl = mc_sys_fcntl((mc_i32)fd, MC_F_GETFL, 0);
	if (fl >= 0) {
		(void)mc_sys_fcntl((mc_i32)fd, MC_F_SETFL, (mc_i64)((mc_u64)fl & ~(mc_u64)MC_O_NONBLOCK));
	}
	return fd;
}
