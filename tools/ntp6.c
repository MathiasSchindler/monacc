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

static MC_NORETURN void ntp6_usage(const char *argv0) {
	mc_die_usage(argv0, "ntp6 [-s DNS_SERVER] [-W TIMEOUT_MS] [SERVER]");
}

static void write_u32_9digits(mc_i32 fd, mc_u32 v) {
	char tmp[9];
	for (int i = 8; i >= 0; i--) {
		tmp[i] = (char)('0' + (v % 10u));
		v /= 10u;
	}
	(void)mc_write_all(fd, tmp, sizeof(tmp));
}

static int ntp6_query_once(const char *argv0, const mc_u8 ip6[16], mc_u32 timeout_ms, mc_u64 *out_unix_sec, mc_u32 *out_unix_nsec) {
	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = mc_htons(123);
	for (int i = 0; i < 16; i++) dst.sin6_addr.s6_addr[i] = ip6[i];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_DGRAM | MC_SOCK_CLOEXEC, MC_IPPROTO_UDP);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	mc_i64 r = mc_sys_connect((mc_i32)fd, &dst, (mc_u32)sizeof(dst));
	if (r < 0) {
		(void)mc_sys_close((mc_i32)fd);
		return 0;
	}

	mc_u8 req[48];
	mc_memset(req, 0, sizeof(req));
	// LI=0, VN=4, Mode=3 (client)
	req[0] = 0x23;

	r = mc_sys_sendto((mc_i32)fd, req, sizeof(req), 0, 0, 0);
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

	mc_u8 resp[64];
	mc_i64 nr = mc_sys_recvfrom((mc_i32)fd, resp, sizeof(resp), 0, 0, 0);
	(void)mc_sys_close((mc_i32)fd);
	if (nr < 48) return 0;

	mc_u8 li_vn_mode = resp[0];
	mc_u8 mode = (mc_u8)(li_vn_mode & 0x7u);
	if (mode != 4 && mode != 5) {
		// 4=server, 5=broadcast
		return 0;
	}

	// Transmit Timestamp (server time): bytes 40..47
	mc_u32 sec = (mc_u32)((mc_u32)resp[40] << 24) | (mc_u32)((mc_u32)resp[41] << 16) | (mc_u32)((mc_u32)resp[42] << 8) | (mc_u32)resp[43];
	mc_u32 frac = (mc_u32)((mc_u32)resp[44] << 24) | (mc_u32)((mc_u32)resp[45] << 16) | (mc_u32)((mc_u32)resp[46] << 8) | (mc_u32)resp[47];

	// NTP epoch (1900) -> Unix epoch (1970)
	const mc_u64 NTP_UNIX_EPOCH_DELTA = 2208988800ull;
	if ((mc_u64)sec < NTP_UNIX_EPOCH_DELTA) return 0;

	mc_u64 unix_sec = (mc_u64)sec - NTP_UNIX_EPOCH_DELTA;
	mc_u32 unix_nsec = (mc_u32)(((mc_u64)frac * 1000000000ull) >> 32);

	*out_unix_sec = unix_sec;
	*out_unix_nsec = unix_nsec;
	return 1;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "ntp6";

	mc_u32 timeout_ms = 3000;
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
		if (mc_streq(a, "-s")) {
			i++;
			if (i >= argc) ntp6_usage(argv0);
			if (!parse_ipv6_literal(argv[i], dns_server)) ntp6_usage(argv0);
			have_dns_server = 1;
			continue;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) ntp6_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) ntp6_usage(argv0);
			timeout_ms = v;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) ntp6_usage(argv0);
		break;
	}

	const char *server = "pool.ntp.org";
	int server_is_default = 1;
	if (i < argc) {
		if (i + 1 != argc) ntp6_usage(argv0);
		server = argv[i];
		server_is_default = 0;
	}

	mc_u8 ip6[16];
	int have_ip = parse_ipv6_literal(server, ip6);
	if (!have_ip) {
		mc_u8 dns_list[2][16];
		int n_dns = 0;
		if (have_dns_server) {
			for (int k = 0; k < 16; k++) dns_list[0][k] = dns_server[k];
			n_dns = 1;
		} else {
			if (!resolv_conf_pick_v6(dns_list[0])) {
				(void)parse_ipv6_literal("2001:4860:4860::8888", dns_list[0]);
				(void)parse_ipv6_literal("2001:4860:4860::8844", dns_list[1]);
				n_dns = 2;
			} else {
				n_dns = 1;
			}
		}

		static const char *const pool_names[] = { "pool.ntp.org", "0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org" };
		const char *const *names = server_is_default ? pool_names : &server;
		mc_usize n_names = server_is_default ? (mc_usize)(sizeof(pool_names) / sizeof(pool_names[0])) : 1u;

		int ok = 0;
		for (mc_usize ni = 0; ni < n_names && !ok; ni++) {
			for (int di = 0; di < n_dns; di++) {
				if (dns6_resolve_first_aaaa(argv0, dns_list[di], 53, names[ni], timeout_ms, ip6)) {
					ok = 1;
					break;
				}
			}
		}

		if (!ok) {
			(void)mc_write_str(2, argv0);
			(void)mc_write_str(2, ": resolve failed\n");
			return 1;
		}
	}

	mc_u64 unix_sec = 0;
	mc_u32 unix_nsec = 0;
	if (!ntp6_query_once(argv0, ip6, timeout_ms, &unix_sec, &unix_nsec)) {
		(void)mc_write_str(2, argv0);
		(void)mc_write_str(2, ": ntp failed\n");
		return 1;
	}

	(void)mc_write_str(1, "unix=");
	(void)mc_write_u64_dec(1, unix_sec);
	(void)mc_write_str(1, ".");
	write_u32_9digits(1, unix_nsec);
	(void)mc_write_str(1, "\n");
	return 0;
}
