#pragma once

#include "mc.h"

// Fetches an HTTPS resource from `host:443` using the in-tree TLS 1.3 client.
// Extracts the HTTP response body into `out_body`.
//
// Returns 0 on success, non-zero on error.
int masto_http_get_body_via_tls13(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *path,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
);

// Same as masto_http_get_body_via_tls13, but adds an Authorization header.
// `bearer_token` is the raw token value (without the "Bearer " prefix).
int masto_http_get_body_via_tls13_bearer_get(
	const char *argv0,
	const char *host,
	const char *sni,
	const char *path,
	const char *bearer_token,
	char *out_body,
	mc_usize out_cap,
	mc_usize *out_len
);

// Generic HTTP request helper over the in-tree TLS 1.3 client.
// - `method` like "GET" or "POST"
// - `bearer_token` may be NULL
// - `content_type` should be set when body is non-empty
// - Response is parsed; only the response body is returned.
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
);

// Same as masto_http_request_body_via_tls13, but also returns the HTTP status code
// (e.g. 200, 401, 422) in `out_status` if non-NULL.
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
);

// POST application/x-www-form-urlencoded with bearer token.
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
);
