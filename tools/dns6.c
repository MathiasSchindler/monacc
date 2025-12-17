#include "mc.h"
#include "mc_net.h"

static mc_u16 mc_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u32 mc_bswap32(mc_u32 x) {
	return ((x & 0x000000FFu) << 24) | ((x & 0x0000FF00u) << 8) | ((x & 0x00FF0000u) >> 8) | ((x & 0xFF000000u) >> 24);
}

static mc_u16 mc_htons(mc_u16 x) {
	return mc_bswap16(x);
}

static mc_u16 mc_ntohs(mc_u16 x) {
	return mc_bswap16(x);
}

static mc_u32 mc_htonl(mc_u32 x) {
	return mc_bswap32(x);
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

static void format_ipv6(char out[64], const mc_u8 a[16]) {
	mc_u16 w[8];
	for (int i = 0; i < 8; i++) {
		w[i] = (mc_u16)(((mc_u16)a[i * 2] << 8) | (mc_u16)a[i * 2 + 1]);
	}

	int best_i = -1;
	int best_len = 0;
	for (int i = 0; i < 8;) {
		if (w[i] != 0) {
			i++;
			continue;
		}
		int j = i;
		while (j < 8 && w[j] == 0) j++;
		int len = j - i;
		if (len > best_len) {
			best_len = len;
			best_i = i;
		}
		i = j;
	}
	if (best_len < 2) {
		best_i = -1;
		best_len = 0;
	}

	mc_usize n = 0;
	for (int i = 0; i < 8; i++) {
		if (best_i >= 0 && i >= best_i && i < best_i + best_len) {
			if (i == best_i) {
				out[n++] = ':';
				out[n++] = ':';
			}
			continue;
		}
		if (i > 0 && !(best_i >= 0 && i == best_i + best_len)) {
			out[n++] = ':';
		}
		// hex without leading zeros
		mc_u16 v = w[i];
		int started = 0;
		for (int shift = 12; shift >= 0; shift -= 4) {
			mc_u8 nib = (mc_u8)((v >> (mc_u16)shift) & 0xFu);
			if (!started) {
				if (nib == 0 && shift != 0) continue;
				started = 1;
			}
			out[n++] = (nib < 10) ? (char)('0' + nib) : (char)('a' + (nib - 10));
		}
		if (!started) out[n++] = '0';
	}
	if (n == 0) {
		out[n++] = ':';
		out[n++] = ':';
	}
	out[n] = 0;
}

static void dns6_usage(const char *argv0) {
	mc_die_usage(argv0, "dns6 [-t aaaa|ptr] [-s SERVER] [-p PORT] [-W TIMEOUT_MS] [--tcp] NAME");
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
		// find line
		const char *line = p;
		while (*p && *p != '\n') p++;
		const char *end = p;
		if (*p == '\n') p++;

		// skip leading spaces
		while (line < end && (*line == ' ' || *line == '\t')) line++;
		// ignore comments/empty
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
		// token
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
			// compression pointer
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

static int dns_name_decode_rec(const mc_u8 *msg, mc_usize msglen, mc_usize off, char *out, mc_usize cap, mc_usize *io_n, int depth) {
	if (depth > 16) return 0;
	mc_usize o = off;
	for (;;) {
		if (o >= msglen) return 0;
		mc_u8 len = msg[o++];
		if (len == 0) return 1;
		if ((len & 0xC0u) == 0xC0u) {
			if (o >= msglen) return 0;
			mc_u16 ptr = (mc_u16)(((mc_u16)(len & 0x3Fu) << 8) | (mc_u16)msg[o]);
			o++;
			return dns_name_decode_rec(msg, msglen, (mc_usize)ptr, out, cap, io_n, depth + 1);
		}
		if (len > 63) return 0;
		if (o + len > msglen) return 0;
		if (*io_n != 0) {
			if (*io_n + 1 >= cap) return 0;
			out[(*io_n)++] = '.';
		}
		for (mc_usize i = 0; i < (mc_usize)len; i++) {
			mc_u8 c = msg[o + i];
			if (c < 32 || c >= 127) c = (mc_u8)'?';
			if (*io_n + 1 >= cap) return 0;
			out[(*io_n)++] = (char)c;
		}
		o += len;
	}
}

static int dns_name_decode(const mc_u8 *msg, mc_usize msglen, mc_usize off, char *out, mc_usize cap) {
	mc_usize n = 0;
	if (!dns_name_decode_rec(msg, msglen, off, out, cap, &n, 0)) return 0;
	if (n >= cap) return 0;
	out[n] = 0;
	return 1;
}

static int make_ptr_qname(char out[96], const mc_u8 ip6[16]) {
	// 32 nibbles reversed, dot-separated, then ip6.arpa
	static const char hex[] = "0123456789abcdef";
	mc_usize n = 0;
	for (int i = 15; i >= 0; i--) {
		mc_u8 b = ip6[i];
		mc_u8 lo = (mc_u8)(b & 0xFu);
		mc_u8 hi = (mc_u8)((b >> 4) & 0xFu);
		if (n + 4 >= sizeof(out)) return 0;
		out[n++] = hex[lo];
		out[n++] = '.';
		out[n++] = hex[hi];
		out[n++] = '.';
	}
	const char *suf = "ip6.arpa";
	for (mc_usize i = 0; suf[i]; i++) {
		if (n + 2 >= sizeof(out)) return 0;
		out[n++] = suf[i];
	}
	out[n] = 0;
	return 1;
}

static int do_dns_query(const char *argv0, const mc_u8 server_ip[16], mc_u16 server_port, int use_tcp, mc_i32 timeout_ms, mc_u16 qtype,
	const char *qname) {
	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = mc_htons(server_port);
	for (int i = 0; i < 16; i++) sa.sin6_addr.s6_addr[i] = server_ip[i];

	mc_i32 stype = use_tcp ? MC_SOCK_STREAM : MC_SOCK_DGRAM;
	mc_i32 proto = use_tcp ? MC_IPPROTO_TCP : MC_IPPROTO_UDP;

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, stype | MC_SOCK_CLOEXEC, proto);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	mc_i64 r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
	if (r < 0) mc_die_errno(argv0, "connect", r);

	mc_u8 q[512];
	mc_usize qn = 0;
	mc_u16 id = dns_pick_id();

	// Header
	if (sizeof(q) < 12) mc_die_errno(argv0, "dns", (mc_i64)-MC_EINVAL);
	q[0] = (mc_u8)(id >> 8);
	q[1] = (mc_u8)(id & 0xFFu);
	q[2] = 0x01; // RD
	q[3] = 0x00;
	q[4] = 0;
	q[5] = 1; // QDCOUNT
	q[6] = 0;
	q[7] = 0; // ANCOUNT
	q[8] = 0;
	q[9] = 0; // NSCOUNT
	q[10] = 0;
	q[11] = 0; // ARCOUNT
	qn = 12;

	if (!dns_encode_qname(q, sizeof(q), qname, &qn)) {
		mc_die_errno(argv0, "qname", (mc_i64)-MC_EINVAL);
	}
	if (qn + 4 > sizeof(q)) {
		mc_die_errno(argv0, "dns", (mc_i64)-MC_EINVAL);
	}
	q[qn++] = (mc_u8)(qtype >> 8);
	q[qn++] = (mc_u8)(qtype & 0xFFu);
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

	r = mc_sys_sendto((mc_i32)fd, sendbuf, sendlen, 0, 0, 0);
	if (r < 0) mc_die_errno(argv0, "send", r);

	struct mc_pollfd pfd;
	pfd.fd = (mc_i32)fd;
	pfd.events = MC_POLLIN;
	pfd.revents = 0;
	for (;;) {
		mc_i64 pr = mc_sys_poll(&pfd, 1, timeout_ms);
		if (pr < 0) {
			if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
			mc_die_errno(argv0, "poll", pr);
		}
		if (pr == 0) {
			mc_print_errno(argv0, "dns", (mc_i64)-MC_ETIMEDOUT);
			(void)mc_sys_close((mc_i32)fd);
			return 1;
		}
		break;
	}

	mc_u8 ans[1536];
	mc_i64 nr = mc_sys_recvfrom((mc_i32)fd, ans, sizeof(ans), 0, 0, 0);
	(void)mc_sys_close((mc_i32)fd);
	if (nr < 0) mc_die_errno(argv0, "recv", nr);
	if (nr < 12) {
		mc_print_errno(argv0, "dns", (mc_i64)-MC_EINVAL);
		return 1;
	}

	mc_usize msglen = (mc_usize)nr;
	mc_u16 rid = (mc_u16)(((mc_u16)ans[0] << 8) | (mc_u16)ans[1]);
	if (rid != id) {
		mc_print_errno(argv0, "dns", (mc_i64)-MC_EINVAL);
		return 1;
	}
	mc_u16 flags = (mc_u16)(((mc_u16)ans[2] << 8) | (mc_u16)ans[3]);
	int tc = (flags & 0x0200u) ? 1 : 0;
	int rcode = (int)(flags & 0x000Fu);
	if ((flags & 0x8000u) == 0) {
		mc_print_errno(argv0, "dns", (mc_i64)-MC_EINVAL);
		return 1;
	}
	if (rcode != 0) {
		return 1;
	}

	mc_u16 qd = (mc_u16)(((mc_u16)ans[4] << 8) | (mc_u16)ans[5]);
	mc_u16 an = (mc_u16)(((mc_u16)ans[6] << 8) | (mc_u16)ans[7]);

	mc_usize off = 12;
	for (mc_u16 qi = 0; qi < qd; qi++) {
		mc_usize noff;
		if (!dns_name_skip(ans, msglen, off, &noff)) return 1;
		off = noff;
		if (off + 4 > msglen) return 1;
		off += 4;
	}

	int printed = 0;
	for (mc_u16 ai = 0; ai < an; ai++) {
		mc_usize noff;
		if (!dns_name_skip(ans, msglen, off, &noff)) return printed ? 0 : 1;
		off = noff;
		if (off + 10 > msglen) return printed ? 0 : 1;
		mc_u16 atype = (mc_u16)(((mc_u16)ans[off] << 8) | (mc_u16)ans[off + 1]);
		mc_u16 aclass = (mc_u16)(((mc_u16)ans[off + 2] << 8) | (mc_u16)ans[off + 3]);
		(void)aclass;
		mc_u32 ttl = (mc_u32)(((mc_u32)ans[off + 4] << 24) | ((mc_u32)ans[off + 5] << 16) | ((mc_u32)ans[off + 6] << 8) | (mc_u32)ans[off + 7]);
		(void)ttl;
		mc_u16 rdlen = (mc_u16)(((mc_u16)ans[off + 8] << 8) | (mc_u16)ans[off + 9]);
		off += 10;
		if (off + rdlen > msglen) return printed ? 0 : 1;

		if (atype == 28 && qtype == 28 && rdlen == 16) {
			char ipbuf[64];
			format_ipv6(ipbuf, ans + off);
			mc_i64 wr = mc_write_str(1, ipbuf);
			if (wr < 0) mc_die_errno(argv0, "write", wr);
			wr = mc_write_all(1, "\n", 1);
			if (wr < 0) mc_die_errno(argv0, "write", wr);
			printed = 1;
		}

		if (atype == 12 && qtype == 12) {
			char namebuf[256];
			if (dns_name_decode(ans, msglen, off, namebuf, sizeof(namebuf))) {
				mc_i64 wr = mc_write_str(1, namebuf);
				if (wr < 0) mc_die_errno(argv0, "write", wr);
				wr = mc_write_all(1, "\n", 1);
				if (wr < 0) mc_die_errno(argv0, "write", wr);
				printed = 1;
			}
		}

		off += rdlen;
	}

	if (!use_tcp && tc) {
		// Caller will retry via TCP.
		return 2;
	}

	return printed ? 0 : 1;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "dns6";

	mc_u16 qtype = 28; // AAAA
	mc_u16 port = 53;
	mc_i32 timeout_ms = 1000;
	int force_tcp = 0;

	mc_u8 server[16];
	int have_server = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "--tcp")) {
			force_tcp = 1;
			continue;
		}
		if (mc_streq(a, "-t")) {
			i++;
			if (i >= argc) dns6_usage(argv0);
			const char *t = argv[i];
			if (mc_streq(t, "aaaa")) {
				qtype = 28;
			} else if (mc_streq(t, "ptr")) {
				qtype = 12;
			} else {
				dns6_usage(argv0);
			}
			continue;
		}
		if (mc_streq(a, "-s")) {
			i++;
			if (i >= argc) dns6_usage(argv0);
			if (!parse_ipv6_literal(argv[i], server)) dns6_usage(argv0);
			have_server = 1;
			continue;
		}
		if (mc_streq(a, "-p")) {
			i++;
			if (i >= argc) dns6_usage(argv0);
			mc_u32 pv = 0;
			if (mc_parse_u32_dec(argv[i], &pv) != 0 || pv == 0 || pv > 65535u) dns6_usage(argv0);
			port = (mc_u16)pv;
			continue;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) dns6_usage(argv0);
			mc_u32 tv = 0;
			if (mc_parse_u32_dec(argv[i], &tv) != 0) dns6_usage(argv0);
			timeout_ms = (mc_i32)tv;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) dns6_usage(argv0);
		break;
	}

	if (i + 1 != argc) dns6_usage(argv0);
	const char *arg = argv[i];

	int default_google = 0;
	if (!have_server) {
		if (!resolv_conf_pick_v6(server)) {
			// Temporary default: Google Public DNS (IPv6)
			(void)parse_ipv6_literal("2001:4860:4860::8888", server);
			default_google = 1;
		}
	}

	char qname[256];
	const char *qname_p = arg;
	if (qtype == 12) {
		mc_u8 ip6[16];
		if (!parse_ipv6_literal(arg, ip6)) dns6_usage(argv0);
		if (!make_ptr_qname(qname, ip6)) {
			mc_die_errno(argv0, "ptr", (mc_i64)-MC_EINVAL);
		}
		qname_p = qname;
	}

	int rc = do_dns_query(argv0, server, port, force_tcp, timeout_ms, qtype, qname_p);
	if (rc == 2) {
		// UDP truncated -> retry TCP.
		rc = do_dns_query(argv0, server, port, 1, timeout_ms, qtype, qname_p);
		if (rc == 2) rc = 1;
	}
	if (rc != 0 && default_google) {
		mc_u8 server2[16];
		(void)parse_ipv6_literal("2001:4860:4860::8844", server2);
		rc = do_dns_query(argv0, server2, port, force_tcp, timeout_ms, qtype, qname_p);
		if (rc == 2) {
			rc = do_dns_query(argv0, server2, port, 1, timeout_ms, qtype, qname_p);
			if (rc == 2) rc = 1;
		}
	}
	return rc;
}
