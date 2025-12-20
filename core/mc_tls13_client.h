#pragma once

#include "mc_types.h"

// Minimal TLS 1.3 client state for tool-to-core reuse.
//
// This is intentionally small and pragmatic:
// - No certificate validation
// - Only the subset needed by existing tls13 tool and higher-level clients
// - IPv6/DNS/connect handled by tools; core operates on an already-connected fd

struct mc_tls13_client {
	mc_i32 fd;
	mc_u32 timeout_ms;
	int debug;

	mc_u8 c_ap_key[16];
	mc_u8 c_ap_iv[12];
	mc_u8 s_ap_key[16];
	mc_u8 s_ap_iv[12];
	mc_u64 c_ap_seq;
	mc_u64 s_ap_seq;

	int handshake_done;
};

void mc_tls13_client_init(struct mc_tls13_client *c, mc_i32 fd, mc_u32 timeout_ms);

// Performs a live TLS 1.3 handshake on c->fd and derives application traffic keys.
// sni may be NULL to omit SNI; if provided, length must be 1..255.
// Returns 0 on success, -1 on error.
int mc_tls13_client_handshake(struct mc_tls13_client *c, const char *sni, mc_usize sni_len);

// Encrypts and writes application data.
// Returns total bytes written from plaintext (len) on success, -1 on error.
mc_i64 mc_tls13_client_write_app(struct mc_tls13_client *c, const mc_u8 *buf, mc_usize len);

// Reads and decrypts the next application-data plaintext chunk.
// Returns:
// - >0: number of plaintext bytes written to buf
// - 0: orderly TLS close (close_notify) / EOF
// - -1: error
mc_i64 mc_tls13_client_read_app(struct mc_tls13_client *c, mc_u8 *buf, mc_usize cap);

// Sends an encrypted close_notify alert.
// Returns 0 on success, -1 on error.
int mc_tls13_client_close_notify(struct mc_tls13_client *c);
