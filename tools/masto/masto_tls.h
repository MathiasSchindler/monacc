#pragma once

#include "mc.h"

struct masto_tls13 {
	mc_i32 fd;

	mc_u8 c_app_key[16];
	mc_u8 c_app_iv[12];
	mc_u8 s_app_key[16];
	mc_u8 s_app_iv[12];
	mc_u64 c_app_seq;
	mc_u64 s_app_seq;
};

// Performs a TLS 1.3 handshake to `sni` over the already-connected TCP socket.
// Certificate validation is NOT performed.
// Returns 0 on success.
int masto_tls13_handshake(struct masto_tls13 *out, mc_i32 fd, const char *sni);
