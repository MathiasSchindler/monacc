#include "mc.h"
#include "mc_net.h"

static mc_u16 mc_bswap16(mc_u16 x) {
	return (mc_u16)((mc_u16)(x << 8) | (mc_u16)(x >> 8));
}

static mc_u16 mc_htons(mc_u16 x) {
	// Linux x86_64 is little-endian.
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

		// Parse 1..4 hex digits.
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

static void tcp6_usage(const char *argv0) {
	mc_die_usage(argv0, "tcp6 [-W TIMEOUT_MS] IPV6 PORT");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tcp6";

	mc_i32 timeout_ms = -1;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-W")) {
			i++;
			if (i >= argc) tcp6_usage(argv0);
			mc_u32 v = 0;
			if (mc_parse_u32_dec(argv[i], &v) != 0) tcp6_usage(argv0);
			timeout_ms = (mc_i32)v;
			continue;
		}
		if (a[0] == '-' && a[1] != 0) {
			tcp6_usage(argv0);
		}
		break;
	}

	if (i + 2 != argc) tcp6_usage(argv0);
	const char *ip = argv[i];
	const char *port_s = argv[i + 1];

	mc_u32 port_u32 = 0;
	if (mc_parse_u32_dec(port_s, &port_u32) != 0 || port_u32 == 0 || port_u32 > 65535u) {
		tcp6_usage(argv0);
	}

	struct mc_sockaddr_in6 sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sin6_family = (mc_u16)MC_AF_INET6;
	sa.sin6_port = mc_htons((mc_u16)port_u32);
	if (!parse_ipv6_literal(ip, sa.sin6_addr.s6_addr)) {
		mc_die_usage(argv0, "tcp6 [-W TIMEOUT_MS] IPV6 PORT");
	}

	mc_i64 fd = mc_sys_socket(MC_AF_INET6, MC_SOCK_STREAM | MC_SOCK_CLOEXEC, MC_IPPROTO_TCP);
	if (fd < 0) mc_die_errno(argv0, "socket", fd);

	mc_i64 r;
	if (timeout_ms >= 0) {
		mc_i64 fl = mc_sys_fcntl((mc_i32)fd, MC_F_GETFL, 0);
		if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
		fl = mc_sys_fcntl((mc_i32)fd, MC_F_SETFL, (mc_i64)((mc_u64)fl | (mc_u64)MC_O_NONBLOCK));
		if (fl < 0) mc_die_errno(argv0, "fcntl", fl);

		r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0 && (mc_u64)(-r) != (mc_u64)MC_EINPROGRESS) {
			mc_die_errno(argv0, "connect", r);
		}

		struct mc_pollfd pfd;
		pfd.fd = (mc_i32)fd;
		pfd.events = MC_POLLOUT;
		pfd.revents = 0;

		for (;;) {
			mc_i64 pr = mc_sys_poll(&pfd, 1, timeout_ms);
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

		// Determine final status by retrying connect().
		r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) {
			mc_u64 e = (mc_u64)(-r);
			if (e != (mc_u64)MC_EISCONN) {
				mc_die_errno(argv0, "connect", r);
			}
		}
	} else {
		r = mc_sys_connect((mc_i32)fd, &sa, (mc_u32)sizeof(sa));
		if (r < 0) mc_die_errno(argv0, "connect", r);
	}

	(void)mc_sys_close((mc_i32)fd);
	return 0;
}
