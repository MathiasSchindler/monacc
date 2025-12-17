#include "mc.h"
#include "mc_net.h"

static mc_u16 mc_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u16 mc_htons(mc_u16 x) {
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
		if (parse_ipv6_literal(tmp, out_server)) return 1;
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

static MC_NORETURN void nc6_usage(const char *argv0) {
	mc_die_usage(argv0,
		"nc6 [-l] [-s BIND_ADDR] [-p PORT] [-W TIMEOUT_MS] [-D DNS_SERVER] HOST PORT\n"
		"nc6 -l [-s BIND_ADDR] -p PORT [-W TIMEOUT_MS]" );
}

static int connect_with_timeout(const char *argv0, mc_i32 fd, const void *sa, mc_u32 salen, mc_u32 timeout_ms) {
	if (timeout_ms == 0) {
		mc_i64 r = mc_sys_connect(fd, sa, salen);
		return (r < 0) ? 0 : 1;
	}

	mc_i64 fl = mc_sys_fcntl(fd, MC_F_GETFL, 0);
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
	mc_i64 r = mc_sys_fcntl(fd, MC_F_SETFL, (mc_i64)((mc_u64)fl | (mc_u64)MC_O_NONBLOCK));
	if (r < 0) mc_die_errno(argv0, "fcntl", r);

	r = mc_sys_connect(fd, sa, salen);
	if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EINPROGRESS) return 0;

	struct mc_pollfd pfd;
	pfd.fd = fd;
	pfd.events = MC_POLLOUT;
	pfd.revents = 0;
	for (;;) {
		mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
		if (pr < 0) {
			if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
			mc_die_errno(argv0, "poll", pr);
		}
		if (pr == 0) return 0;
		break;
	}

	r = mc_sys_connect(fd, sa, salen);
	if (r < 0) {
		mc_u64 e = (mc_u64)(-r);
		if (e != (mc_u64)MC_EISCONN) return 0;
	}

	// restore blocking
	r = mc_sys_fcntl(fd, MC_F_SETFL, fl);
	if (r < 0) mc_die_errno(argv0, "fcntl", r);
	return 1;
}

static int pump_bidirectional(const char *argv0, mc_i32 sockfd) {
	mc_u8 buf[4096];
	int stdin_open = 1;
	int sock_open = 1;

	for (;;) {
		if (!sock_open) return 0;

		struct mc_pollfd pfds[2];
		mc_u32 nfds = 0;
		mc_u32 idx_stdin = 0;
		mc_u32 idx_sock = 0;

		if (stdin_open) {
			idx_stdin = nfds;
			pfds[nfds].fd = 0;
			pfds[nfds].events = MC_POLLIN;
			pfds[nfds].revents = 0;
			nfds++;
		}
		idx_sock = nfds;
		pfds[nfds].fd = sockfd;
		pfds[nfds].events = MC_POLLIN;
		pfds[nfds].revents = 0;
		nfds++;

		mc_i64 pr;
		for (;;) {
			pr = mc_sys_poll(pfds, nfds, -1);
			if (pr < 0) {
				if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
				mc_die_errno(argv0, "poll", pr);
			}
			break;
		}

		if (stdin_open && (pfds[idx_stdin].revents & MC_POLLIN)) {
			mc_i64 nr = mc_sys_read(0, buf, sizeof(buf));
			if (nr < 0) mc_die_errno(argv0, "read", nr);
			if (nr == 0) {
				stdin_open = 0;
				(void)mc_sys_shutdown(sockfd, MC_SHUT_WR);
			} else {
				mc_i64 wr = mc_write_all(sockfd, buf, (mc_usize)nr);
				if (wr < 0) {
					// peer closed? just stop
					stdin_open = 0;
					(void)mc_sys_shutdown(sockfd, MC_SHUT_WR);
				}
			}
		}

		if (pfds[idx_sock].revents & (MC_POLLIN | MC_POLLHUP)) {
			mc_i64 nr = mc_sys_read(sockfd, buf, sizeof(buf));
			if (nr < 0) mc_die_errno(argv0, "read", nr);
			if (nr == 0) {
				sock_open = 0;
				return 0;
			}
			mc_i64 wr = mc_write_all(1, buf, (mc_usize)nr);
			if (wr < 0) mc_die_errno(argv0, "write", wr);
		}
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "nc6";

	int listen_mode = 0;
	mc_u32 timeout_ms = 5000;

	mc_u16 port = 0;
	const char *host = 0;

	mc_u8 bind_ip[16];
	int have_bind_ip = 0;

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
		if (mc_streq(a, "-l")) {
			listen_mode = 1;
			continue;
		}
		if (mc_streq(a, "-s")) {
			i++;
			if (i >= argc) nc6_usage(argv0);
			if (!parse_ipv6_literal(argv[i], bind_ip)) nc6_usage(argv0);
			have_bind_ip = 1;
			continue;
		}
		if (mc_streq(a, "-D")) {
			i++;
			if (i >= argc) nc6_usage(argv0);
			if (!parse_ipv6_literal(argv[i], dns_server)) nc6_usage(argv0);
			have_dns_server = 1;
			continue;
		}
		if (mc_streq(a, "-p")) {
			i++;
			if (i >= argc) nc6_usage(argv0);
			mc_u32 pv = 0;
			if (mc_parse_u32_dec(argv[i], &pv) != 0 || pv == 0 || pv > 65535u) nc6_usage(argv0);
			port = (mc_u16)pv;
			continue;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) nc6_usage(argv0);
			mc_u32 tv = 0;
			if (mc_parse_u32_dec(argv[i], &tv) != 0) nc6_usage(argv0);
			timeout_ms = tv;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) nc6_usage(argv0);
		break;
	}

	if (listen_mode) {
		if (port == 0) {
			// allow: nc6 -l PORT
			if (i + 1 != argc) nc6_usage(argv0);
			mc_u32 pv = 0;
			if (mc_parse_u32_dec(argv[i], &pv) != 0 || pv == 0 || pv > 65535u) nc6_usage(argv0);
			port = (mc_u16)pv;
		} else {
			if (i != argc) nc6_usage(argv0);
		}

		struct mc_sockaddr_in6 sa;
		mc_memset(&sa, 0, sizeof(sa));
		sa.sin6_family = (mc_u16)MC_AF_INET6;
		sa.sin6_port = mc_htons(port);
		if (have_bind_ip) {
			for (int k = 0; k < 16; k++) sa.sin6_addr.s6_addr[k] = bind_ip[k];
		}

		mc_i64 lfd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
		if (lfd < 0) mc_die_errno(argv0, "socket", lfd);

		mc_i32 one = 1;
		(void)mc_sys_setsockopt((mc_i32)lfd, MC_SOL_SOCKET, MC_SO_REUSEADDR, &one, (mc_u32)sizeof(one));

		mc_i64 r = mc_sys_bind((mc_i32)lfd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) mc_die_errno(argv0, "bind", r);
		r = mc_sys_listen((mc_i32)lfd, 16);
		if (r < 0) mc_die_errno(argv0, "listen", r);

		struct mc_pollfd pfd;
		pfd.fd = (mc_i32)lfd;
		pfd.events = MC_POLLIN;
		pfd.revents = 0;
		for (;;) {
			mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)timeout_ms);
			if (pr < 0) {
				if ((mc_u64)(-pr) == (mc_u64)MC_EINTR) continue;
				mc_die_errno(argv0, "poll", pr);
			}
			if (pr == 0) {
				mc_print_errno(argv0, "accept", (mc_i64)-MC_ETIMEDOUT);
				(void)mc_sys_close((mc_i32)lfd);
				return 1;
			}
			break;
		}

		struct mc_sockaddr_in6 peer;
		mc_u32 plen = (mc_u32)sizeof(peer);
		mc_memset(&peer, 0, sizeof(peer));
		mc_i64 cfd = mc_sys_accept((mc_i32)lfd, &peer, &plen);
		(void)mc_sys_close((mc_i32)lfd);
		if (cfd < 0) mc_die_errno(argv0, "accept", cfd);

		int rc = pump_bidirectional(argv0, (mc_i32)cfd);
		(void)mc_sys_close((mc_i32)cfd);
		return rc;
	}

	// client mode: require host + port
	if (i + 2 != argc) nc6_usage(argv0);
	host = argv[i];
	mc_u32 pv = 0;
	if (mc_parse_u32_dec(argv[i + 1], &pv) != 0 || pv == 0 || pv > 65535u) nc6_usage(argv0);
	port = (mc_u16)pv;

	mc_u8 dst_ip[16];
	if (!parse_ipv6_literal(host, dst_ip)) {
		if (!have_dns_server) {
			if (!resolv_conf_pick_v6(dns_server)) {
				(void)parse_ipv6_literal("2001:4860:4860::8888", dns_server);
			}
			have_dns_server = 1;
		}
		if (!dns6_resolve_first_aaaa(argv0, dns_server, 53, host, timeout_ms, dst_ip)) {
			// secondary google
			mc_u8 dns2[16];
			(void)parse_ipv6_literal("2001:4860:4860::8844", dns2);
			if (!dns6_resolve_first_aaaa(argv0, dns2, 53, host, timeout_ms, dst_ip)) {
				(void)mc_write_str(2, argv0);
				(void)mc_write_str(2, ": resolve failed\n");
				return 1;
			}
		}
	}

	struct mc_sockaddr_in6 dst;
	mc_memset(&dst, 0, sizeof(dst));
	dst.sin6_family = (mc_u16)MC_AF_INET6;
	dst.sin6_port = mc_htons(port);
	for (int k = 0; k < 16; k++) dst.sin6_addr.s6_addr[k] = dst_ip[k];

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	if (!connect_with_timeout(argv0, (mc_i32)fd, &dst, (mc_u32)sizeof(dst), timeout_ms)) {
		mc_print_errno(argv0, "connect", (mc_i64)-MC_ETIMEDOUT);
		(void)mc_sys_close((mc_i32)fd);
		return 1;
	}

	int rc = pump_bidirectional(argv0, (mc_i32)fd);
	(void)mc_sys_close((mc_i32)fd);
	return rc;
}
