#include "masto_http.h"

#include "masto_dns.h"
#include "mc_tls13_client.h"

static const char *memmem_lit(const char *hay, mc_usize hay_len, const char *needle) {
	mc_usize nlen = mc_strlen(needle);
	if (nlen == 0) return hay;
	if (hay_len < nlen) return MC_NULL;
	for (mc_usize i = 0; i + nlen <= hay_len; i++) {
		if (mc_memcmp(hay + i, needle, nlen) == 0) return hay + i;
	}
	return MC_NULL;
}

static int write_all(mc_i32 fd, const char *buf, mc_usize len) {
	mc_usize off = 0;
	while (off < len) {
		mc_i64 w = mc_sys_write(fd, buf + off, len - off);
		if (w <= 0) return 1;
		off += (mc_usize)w;
	}
	return 0;
}

static int append_cstr(char *out, mc_usize out_cap, mc_usize *io_off, const char *s) {
	mc_usize o = *io_off;
	mc_usize n = mc_strlen(s);
	if (o + n >= out_cap) return 1;
	mc_memcpy(out + o, s, n);
	*io_off = o + n;
	return 0;
}

static int append_u64_dec(char *out, mc_usize out_cap, mc_usize *io_off, mc_u64 v) {
	char tmp[32];
	if (mc_snprint_cstr_u64_cstr(tmp, sizeof(tmp), "", v, "") <= 0) return 1;
	return append_cstr(out, out_cap, io_off, tmp);
}

static int parse_u64_dec(const char *s, mc_usize n, mc_u64 *out) {
	mc_u64 v = 0;
	mc_usize i = 0;
	int any = 0;
	while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
	for (; i < n; i++) {
		char c = s[i];
		if (c < '0' || c > '9') break;
		any = 1;
		mc_u64 nv = v * 10u + (mc_u64)(c - '0');
		if (nv < v) return -1;
		v = nv;
	}
	if (!any) return -1;
	*out = v;
	return 0;
}

static int http_parse_status_code(const char *buf, mc_usize buf_len, mc_i32 *out_status) {
	// Parse: HTTP/1.1 200 OK\r\n
	if (!out_status) return 0;
	*out_status = 0;
	if (!buf || buf_len == 0) return 1;
	const char *http = memmem_lit(buf, buf_len, "HTTP/");
	if (!http) return 1;
	mc_usize http_off = (mc_usize)(http - buf);
	mc_usize rem = buf_len - http_off;
	// Find end of status line.
	mc_usize i = 0;
	while (i < rem && http[i] != '\n') i++;
	mc_usize line_len = i;
	if (line_len > 0 && http[line_len - 1u] == '\r') line_len--;
	// Find first space.
	mc_usize sp = 0;
	while (sp < line_len && http[sp] != ' ') sp++;
	if (sp >= line_len) return 1;
	// Skip spaces.
	while (sp < line_len && http[sp] == ' ') sp++;
	if (sp + 3u > line_len) return 1;
	// Parse 3 digits.
	mc_i32 code = 0;
	for (mc_usize k = 0; k < 3u; k++) {
		char c = http[sp + k];
		if (c < '0' || c > '9') return 1;
		code = code * 10 + (mc_i32)(c - '0');
	}
	*out_status = code;
	return 0;
}

static int ascii_ieq_n(const char *a, const char *b, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) {
		char x = a[i];
		char y = b[i];
		if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
		if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
		if (x != y) return 0;
	}
	return 1;
}

static int ascii_contains_ci(const char *s, mc_usize n, const char *needle) {
	mc_usize m = mc_strlen(needle);
	if (m == 0) return 1;
	if (n < m) return 0;
	for (mc_usize i = 0; i + m <= n; i++) {
		if (ascii_ieq_n(s + i, needle, m)) return 1;
	}
	return 0;
}

static int parse_hex_u64(const char *s, mc_usize n, mc_u64 *out, mc_usize *out_used) {
	if (!out || !out_used) return 1;
	mc_u64 v = 0;
	mc_usize i = 0;
	int any = 0;
	while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
	for (; i < n; i++) {
		char c = s[i];
		mc_u64 d;
		if (c >= '0' && c <= '9') d = (mc_u64)(c - '0');
		else if (c >= 'a' && c <= 'f') d = (mc_u64)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F') d = (mc_u64)(c - 'A' + 10);
		else break;
		any = 1;
		mc_u64 nv = (v << 4) | d;
		if (nv < v) return 1;
		v = nv;
	}
	if (!any) return 1;
	*out = v;
	*out_used = i;
	return 0;
}

static int http_dechunk(const char *body, mc_usize body_len, char *out, mc_usize out_cap, mc_usize *out_len) {
	if (!body || !out || out_cap == 0) return 1;
	mc_usize o = 0;
	mc_usize p = 0;
	while (p < body_len) {
		// Read chunk size line.
		mc_usize line_start = p;
		while (p < body_len && body[p] != '\n') p++;
		mc_usize line_end = p;
		if (p < body_len && body[p] == '\n') p++;
		if (line_end > line_start && body[line_end - 1u] == '\r') line_end--;
		mc_usize line_len = (line_end > line_start) ? (line_end - line_start) : 0;
		if (line_len == 0) return 1;

		// Parse hex size, ignoring extensions after ';'.
		mc_usize cut = 0;
		while (cut < line_len && body[line_start + cut] != ';') cut++;
		mc_u64 sz = 0;
		mc_usize used = 0;
		if (parse_hex_u64(body + line_start, cut, &sz, &used) != 0) return 1;
		(void)used;
		if (sz == 0) {
			// Done; ignore optional trailers.
			break;
		}
		if (sz > (mc_u64)(body_len - p)) return 1;
		if (o + (mc_usize)sz + 1u > out_cap) return 1;
		mc_memcpy(out + o, body + p, (mc_usize)sz);
		o += (mc_usize)sz;
		p += (mc_usize)sz;
		// Skip CRLF after chunk.
		if (p < body_len && body[p] == '\r') p++;
		if (p < body_len && body[p] == '\n') p++;
	}
	out[o] = 0;
	if (out_len) *out_len = o;
	return 0;
}

static int http_extract_body(const char *buf, mc_usize buf_len, mc_i32 *out_status, char *out_body, mc_usize out_cap, mc_usize *out_len) {
	// Find the start of the HTTP response (skip tls13 debug lines).
	const char *http = memmem_lit(buf, buf_len, "HTTP/");
	if (!http) return 1;
	(void)http_parse_status_code(buf, buf_len, out_status);
	mc_usize http_off = (mc_usize)(http - buf);
	mc_usize rem = buf_len - http_off;

	// Find end of headers.
	const char *hdr_end = memmem_lit(http, rem, "\r\n\r\n");
	mc_usize delim = 4;
	if (!hdr_end) {
		hdr_end = memmem_lit(http, rem, "\n\n");
		delim = 2;
	}
	if (!hdr_end) return 1;

	mc_usize hdr_len = (mc_usize)(hdr_end - http);
	const char *body = hdr_end + delim;
	if (body < buf || body > buf + buf_len) return 1;
	mc_usize body_avail = (mc_usize)((buf + buf_len) - body);

	// Parse Content-Length if present.
	mc_u64 content_len = 0;
	int have_len = 0;
	int chunked = 0;
	// Iterate header lines.
	mc_usize i = 0;
	while (i < hdr_len) {
		mc_usize line_start = i;
		while (i < hdr_len && http[i] != '\n') i++;
		mc_usize line_end = i;
		if (i < hdr_len && http[i] == '\n') i++;

		// Trim CR.
		if (line_end > line_start && http[line_end - 1u] == '\r') line_end--;
		mc_usize line_len = (line_end > line_start) ? (line_end - line_start) : 0;
		const char *line = http + line_start;

		// Case-insensitive match for "Content-Length:".
		const char *cl = "Content-Length:";
		mc_usize cln = mc_strlen(cl);
		if (line_len >= cln) {
			if (ascii_ieq_n(line, cl, cln)) {
				mc_u64 v = 0;
				if (parse_u64_dec(line + cln, line_len - cln, &v) == 0) {
					content_len = v;
					have_len = 1;
				}
			}
		}

		// Transfer-Encoding: chunked
		const char *te = "Transfer-Encoding:";
		mc_usize ten = mc_strlen(te);
		if (line_len >= ten && ascii_ieq_n(line, te, ten)) {
			if (ascii_contains_ci(line + ten, line_len - ten, "chunked")) {
				chunked = 1;
			}
		}
	}

	if (chunked && !have_len) {
		return http_dechunk(body, body_avail, out_body, out_cap, out_len);
	}

	mc_usize take = body_avail;
	if (have_len && content_len < (mc_u64)take) take = (mc_usize)content_len;
	if (take + 1u > out_cap) return 1;
	mc_memcpy(out_body, body, take);
	out_body[take] = 0;
	if (out_len) *out_len = take;
	return 0;
}

static int tls13_client_exchange(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *req,
	mc_usize req_len,
	char *out,
	mc_usize out_cap,
	mc_usize *out_len
) {
	if (!argv0) argv0 = "masto";
	if (!host || !*host || !sni || !*sni || !req || req_len == 0 || !out || out_cap == 0) return 1;

	struct mc_in6_addr addr;
	if (masto_resolve_aaaa(host, &addr) != 0) return 1;

	mc_i64 fd64 = masto_tcp_connect_v6(&addr, 443, 5000);
	if (fd64 < 0) return 1;
	mc_i32 fd = (mc_i32)fd64;

	struct mc_tls13_client c;
	mc_tls13_client_init(&c, fd, 5000);
	c.debug = 0;
	mc_usize sni_len = mc_strlen(sni);
	if (sni_len == 0 || sni_len > 255u) {
		(void)mc_sys_close(fd);
		return 1;
	}
	if (mc_tls13_client_handshake(&c, sni, sni_len) != 0) {
		(void)mc_sys_close(fd);
		return 1;
	}

	if (mc_tls13_client_write_app(&c, (const mc_u8 *)req, req_len) < 0) {
		(void)mc_sys_close(fd);
		return 1;
	}
	// We expect HTTP/1.1 responses with Connection: close.
	(void)mc_tls13_client_close_notify(&c);

	mc_usize len = 0;
	for (;;) {
		if (len + 1u >= out_cap) {
			(void)mc_sys_close(fd);
			return 1;
		}
		mc_u8 buf[8192];
		mc_i64 rn = mc_tls13_client_read_app(&c, buf, sizeof(buf));
		if (rn > 0) {
			mc_usize take = (mc_usize)rn;
			if (take > out_cap - 1u - len) take = out_cap - 1u - len;
			mc_memcpy(out + len, buf, take);
			len += take;
			if (take < (mc_usize)rn) {
				(void)mc_sys_close(fd);
				return 1;
			}
			continue;
		}
		if (rn == 0) break;
		(void)mc_sys_close(fd);
		return 1;
	}

	(void)mc_sys_close(fd);
	out[len] = 0;
	if (out_len) *out_len = len;
	return 0;
}

static int build_http_request(
	const char *host,
	const char *path,
	const char *method,
	const char *bearer_token,
	const char *content_type,
	const char *body,
	mc_usize body_len,
	char *out,
	mc_usize out_cap,
	mc_usize *out_len
) {
	// Minimal HTTP/1.1 request. Caller ensures host/path are sane.
	mc_usize o = 0;
	if (!method || !*method) method = "GET";
	if (append_cstr(out, out_cap, &o, method) != 0) return 1;
	if (append_cstr(out, out_cap, &o, " ") != 0) return 1;
	if (append_cstr(out, out_cap, &o, path) != 0) return 1;
	if (append_cstr(out, out_cap, &o, " HTTP/1.1\r\nHost: ") != 0) return 1;
	if (append_cstr(out, out_cap, &o, host) != 0) return 1;
	if (append_cstr(out, out_cap, &o, "\r\nAccept: application/json\r\n") != 0) return 1;
	if (append_cstr(out, out_cap, &o, "User-Agent: masto/monacc\r\n") != 0) return 1;
	if (append_cstr(out, out_cap, &o, "Connection: close\r\n") != 0) return 1;
	if (bearer_token && *bearer_token) {
		if (append_cstr(out, out_cap, &o, "Authorization: Bearer ") != 0) return 1;
		if (append_cstr(out, out_cap, &o, bearer_token) != 0) return 1;
		if (append_cstr(out, out_cap, &o, "\r\n") != 0) return 1;
	}
	if (body && body_len) {
		if (!content_type || !*content_type) return 1;
		if (append_cstr(out, out_cap, &o, "Content-Type: ") != 0) return 1;
		if (append_cstr(out, out_cap, &o, content_type) != 0) return 1;
		if (append_cstr(out, out_cap, &o, "\r\n") != 0) return 1;
		if (append_cstr(out, out_cap, &o, "Content-Length: ") != 0) return 1;
		if (append_u64_dec(out, out_cap, &o, (mc_u64)body_len) != 0) return 1;
		if (append_cstr(out, out_cap, &o, "\r\n") != 0) return 1;
	}
	if (append_cstr(out, out_cap, &o, "Connection: close\r\n\r\n") != 0) return 1;
	if (body && body_len) {
		if (o + body_len >= out_cap) return 1;
		mc_memcpy(out + o, body, body_len);
		o += body_len;
	}

	if (o >= out_cap) return 1;
	out[o] = 0;
	if (out_len) *out_len = o;
	return 0;
}

int masto_http_request_body_via_tls13(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *method,
	const char *path,
	const char *bearer_token,
	const char *content_type,
	const char *body,
	mc_usize body_len,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
) {
	return masto_http_request_body_status_via_tls13(
		argv0,
		host,
		sni,
		method,
		path,
		bearer_token,
		content_type,
		body,
		body_len,
		MC_NULL,
		out_body,
		out_cap,
		out_len
	);
}

int masto_http_request_body_status_via_tls13(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *method,
	const char *path,
	const char *bearer_token,
	const char *content_type,
	const char *body,
	mc_usize body_len,
	mc_i32 *out_status,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
) {
	if (!host || !*host || !sni || !*sni || !path || !*path || !method || !*method || !out_body || out_cap == 0) return 1;
	if ((!body || body_len == 0) && content_type) {
		// ignore
	}

	static char req[16384];
	mc_usize req_len = 0;
	if (build_http_request(host, path, method, bearer_token, content_type, body, body_len, req, sizeof(req), &req_len) != 0) return 1;

	static char resp[262144];
	mc_usize resp_len = 0;
	if (tls13_client_exchange(argv0, host, sni, req, req_len, resp, sizeof(resp), &resp_len) != 0) return 1;
	return http_extract_body(resp, resp_len, out_status, out_body, out_cap, out_len);
}

int masto_http_get_body_via_tls13(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *path,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
) {
	return masto_http_request_body_via_tls13(argv0, host, sni, "GET", path, MC_NULL, MC_NULL, MC_NULL, 0, out_body, out_cap, out_len);
}

int masto_http_get_body_via_tls13_bearer_get(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *path,
	const char *bearer_token,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
) {
	if (!bearer_token || !*bearer_token) return 1;
	return masto_http_request_body_via_tls13(argv0, host, sni, "GET", path, bearer_token, MC_NULL, MC_NULL, 0, out_body, out_cap, out_len);
}

int masto_http_post_form_bearer(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *path,
	const char *bearer_token,
	const char *form_body,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
) {
	if (!form_body) form_body = "";
	if (!bearer_token || !*bearer_token) return 1;
	return masto_http_request_body_via_tls13(
		argv0,
		host,
		sni,
		"POST",
		path,
		bearer_token,
		"application/x-www-form-urlencoded",
		form_body,
		mc_strlen(form_body),
		out_body,
		out_cap,
		out_len
	);
}
