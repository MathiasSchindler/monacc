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

static mc_u16 csum_fold(mc_u32 sum) {
	while (sum >> 16) {
		sum = (sum & 0xFFFFu) + (sum >> 16);
	}
	return (mc_u16)(~sum);
}

static mc_u16 csum16_add(mc_u32 sum, const mc_u8 *p, mc_usize n) {
	mc_u32 s = sum;
	mc_usize i = 0;
	while (i + 1 < n) {
		s += (mc_u32)(((mc_u16)p[i] << 8) | (mc_u16)p[i + 1]);
		i += 2;
	}
	if (i < n) {
		s += (mc_u32)((mc_u16)p[i] << 8);
	}
	return csum_fold(s);
}

static mc_u16 icmpv6_checksum(const mc_u8 src[16], const mc_u8 dst[16], const mc_u8 *icmp, mc_usize icmplen) {
	mc_u32 sum = 0;
	// src + dst
	for (int i = 0; i < 16; i += 2) {
		sum += (mc_u32)(((mc_u16)src[i] << 8) | (mc_u16)src[i + 1]);
		sum += (mc_u32)(((mc_u16)dst[i] << 8) | (mc_u16)dst[i + 1]);
	}
	// length (32-bit)
	mc_u32 l = (mc_u32)icmplen;
	sum += (mc_u32)((l >> 16) & 0xFFFFu);
	sum += (mc_u32)(l & 0xFFFFu);
	// next header
	sum += (mc_u32)MC_IPPROTO_ICMPV6;

	mc_usize i = 0;
	while (i + 1 < icmplen) {
		sum += (mc_u32)(((mc_u16)icmp[i] << 8) | (mc_u16)icmp[i + 1]);
		i += 2;
	}
	if (i < icmplen) {
		sum += (mc_u32)((mc_u16)icmp[i] << 8);
	}
	return csum_fold(sum);
}

static void sleep_ms(mc_u32 ms) {
	struct mc_timespec ts;
	ts.tv_sec = (mc_i64)(ms / 1000u);
	ts.tv_nsec = (mc_i64)((ms % 1000u) * 1000000u);
	(void)mc_sys_nanosleep(&ts, 0);
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
		if (r < 0) mc_die_errno(argv0, "connect", r);

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
		mc_u16 ns = (mc_u16)(((mc_u16)ans[8] << 8) | (mc_u16)ans[9]);
		mc_u16 ar = (mc_u16)(((mc_u16)ans[10] << 8) | (mc_u16)ans[11]);

		mc_usize off = 12;
		for (mc_u16 qi = 0; qi < qd; qi++) {
			mc_usize noff;
			if (!dns_name_skip(ans, msglen, off, &noff)) return 0;
			off = noff;
			if (off + 4 > msglen) return 0;
			off += 4;
		}

		mc_u32 total = (mc_u32)an + (mc_u32)ns + (mc_u32)ar;
		for (mc_u32 ai = 0; ai < total; ai++) {
			mc_usize noff;
			if (!dns_name_skip(ans, msglen, off, &noff)) return 0;
			off = noff;
			if (off + 10 > msglen) return 0;
			mc_u16 atype = (mc_u16)(((mc_u16)ans[off] << 8) | (mc_u16)ans[off + 1]);
			mc_u16 rdlen = (mc_u16)(((mc_u16)ans[off + 8] << 8) | (mc_u16)ans[off + 9]);
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

static void ping6_usage(const char *argv0) {
	mc_die_usage(argv0, "ping6 [-c COUNT] [-i INTERVAL_MS] [-W TIMEOUT_MS] [-s DNS_SERVER] HOST");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "ping6";

	mc_u32 count = 0; // 0 = infinite
	mc_u32 interval_ms = 1000;
	mc_u32 timeout_ms = 1000;

	mc_u8 dns_server[16];
	int have_dns_server = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-c")) {
			i++;
			if (i >= argc) ping6_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) ping6_usage(argv0);
			count = v;
			continue;
		}
		if (mc_streq(a, "-i")) {
			i++;
			if (i >= argc) ping6_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) ping6_usage(argv0);
			interval_ms = v;
			continue;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) ping6_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) ping6_usage(argv0);
			timeout_ms = v;
			continue;
		}
		if (mc_streq(a, "-s")) {
			i++;
			if (i >= argc) ping6_usage(argv0);
			if (!parse_ipv6_literal(argv[i], dns_server)) ping6_usage(argv0);
			have_dns_server = 1;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) ping6_usage(argv0);
		break;
	}

	if (i + 1 != argc) ping6_usage(argv0);
	const char *host = argv[i];

	mc_u8 dst_ip[16];
	if (!parse_ipv6_literal(host, dst_ip)) {
		int default_google = 0;
		if (!have_dns_server) {
			if (!resolv_conf_pick_v6(dns_server)) {
				(void)parse_ipv6_literal("2001:4860:4860::8888", dns_server);
				default_google = 1;
			}
			have_dns_server = 1;
		}
		if (!dns6_resolve_first_aaaa(argv0, dns_server, 53, host, timeout_ms, dst_ip)) {
			if (default_google) {
				mc_u8 dns2[16];
				(void)parse_ipv6_literal("2001:4860:4860::8844", dns2);
				if (dns6_resolve_first_aaaa(argv0, dns2, 53, host, timeout_ms, dst_ip)) {
					goto resolved_ok;
				}
			}
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": resolve failed\n");
			return 1;
		}
	}

resolved_ok:;

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = 0;
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = dst_ip[k];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_RAW | MC_SOCK_CLOEXEC, MC_IPPROTO_ICMPV6);
	if (fd < 0) {
		if ((mc_u64)(-fd) == (mc_u64)MC_EPERM) {
			mc_write_str(2, "ping6: need CAP_NET_RAW (try sudo)\n");
			return 2;
		}
		mc_die_errno(argv0, "socket", fd);
	}

	mc_i64 r = mc_sys_connect((mc_i32)fd, &dst, (mc_u32)sizeof(dst));
	if (r < 0) mc_die_errno(argv0, "connect", r);

	// Determine source address chosen by kernel.
	struct mc_sockaddr_in6 src;
	mc_u32 slen = (mc_u32)sizeof(src);
	mc_memset(&src, 0, sizeof(src));
	r = mc_sys_getsockname((mc_i32)fd, &src, &slen);
	if (r < 0) mc_die_errno(argv0, "getsockname", r);
	if (slen < (mc_u32)sizeof(src) || src.sin6_family != (mc_u16)MC_AF_INET6) {
		mc_die_errno(argv0, "getsockname", (mc_i64)-MC_EINVAL);
	}

	// Nonblocking read; we use poll for timeouts.
	mc_i64 fl = mc_sys_fcntl((mc_i32)fd, MC_F_GETFL, 0);
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
	fl = mc_sys_fcntl((mc_i32)fd, MC_F_SETFL, (mc_i64)((mc_u64)fl | (mc_u64)MC_O_NONBLOCK));
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);

	mc_u16 ident = 0;
	(void)mc_sys_getrandom(&ident, sizeof(ident), 0);
	if (ident == 0) ident = (mc_u16)((mc_usize)(void *)&fd & 0xFFFFu);

	char dst_txt[64];
	format_ipv6(dst_txt, dst_ip);

	mc_u32 sent = 0;
	mc_u32 recv_ok = 0;

	for (mc_u32 seq = 1; count == 0 || seq <= count; seq++) {
		mc_u8 pkt[8 + 8];
		mc_usize plen = sizeof(pkt);

		struct mc_timespec t0;
		(void)mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &t0);
		mc_u64 t0ns = (mc_u64)t0.tv_sec * 1000000000ull + (mc_u64)t0.tv_nsec;

		pkt[0] = 128; // Echo Request
		pkt[1] = 0;   // code
		pkt[2] = 0;
		pkt[3] = 0;
		mc_u16 idn = mc_htons(ident);
		pkt[4] = (mc_u8)(idn >> 8);
		pkt[5] = (mc_u8)(idn & 0xFFu);
		mc_u16 sqn = mc_htons((mc_u16)seq);
		pkt[6] = (mc_u8)(sqn >> 8);
		pkt[7] = (mc_u8)(sqn & 0xFFu);
		// payload: t0ns (big-endian)
		for (int b = 0; b < 8; b++) {
			pkt[8 + b] = (mc_u8)((t0ns >> (mc_u64)(56 - 8 * b)) & 0xFFu);
		}

		mc_u16 csum = icmpv6_checksum(src.sin6_addr.s6_addr, dst_ip, pkt, plen);
		pkt[2] = (mc_u8)(csum >> 8);
		pkt[3] = (mc_u8)(csum & 0xFFu);

		mc_i64 sr = mc_sys_sendto((mc_i32)fd, pkt, plen, 0, 0, 0);
		if (sr < 0) mc_die_errno(argv0, "send", sr);
		sent++;

		struct mc_pollfd pfd;
		pfd.fd = (mc_i32)fd;
		pfd.events = MC_POLLIN;
		pfd.revents = 0;

		int got = 0;
		for (;;) {
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr < 0) {
				if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
				mc_die_errno(argv0, "poll", pr);
			}
			if (pr == 0) break;

			mc_u8 in[2048];
			mc_i64 rr = mc_sys_recvfrom((mc_i32)fd, in, sizeof(in), 0, 0, 0);
			if (rr < 0) {
				mc_u64 e = (mc_u64)(-rr);
				if (e == (mc_u64)MC_EAGAIN || e == (mc_u64)MC_EINTR) continue;
				mc_die_errno(argv0, "recv", rr);
			}
			if (rr < 8) continue;
			if (in[0] != 129 || in[1] != 0) continue; // Echo Reply
			mc_u16 rid = mc_ntohs((mc_u16)(((mc_u16)in[4] << 8) | (mc_u16)in[5]));
			mc_u16 rsq = mc_ntohs((mc_u16)(((mc_u16)in[6] << 8) | (mc_u16)in[7]));
			if (rid != ident || rsq != (mc_u16)seq) continue;

			struct mc_timespec t1;
			(void)mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &t1);
			mc_u64 t1ns = (mc_u64)t1.tv_sec * 1000000000ull + (mc_u64)t1.tv_nsec;
			mc_u64 dtns = (t1ns >= t0ns) ? (t1ns - t0ns) : 0;
			mc_u64 ms = (dtns + 500000ull) / 1000000ull;

			(void)mc_write_str(1, "from ");
			(void)mc_write_str(1, dst_txt);
			(void)mc_write_str(1, " seq=");
			(void)mc_write_u64_dec(1, (mc_u64)seq);
			(void)mc_write_str(1, " time=");
			(void)mc_write_u64_dec(1, ms);
			(void)mc_write_str(1, "ms\n");

			got = 1;
			recv_ok++;
			break;
		}

		if (!got) {
			(void)mc_write_str(1, "from ");
			(void)mc_write_str(1, dst_txt);
			(void)mc_write_str(1, " seq=");
			(void)mc_write_u64_dec(1, (mc_u64)seq);
			(void)mc_write_str(1, " timeout\n");
		}

		if (count == 0 || seq < count) {
			sleep_ms(interval_ms);
		}
	}

	(void)mc_sys_close((mc_i32)fd);
	return (sent != 0 && recv_ok == sent) ? 0 : 1;
}
