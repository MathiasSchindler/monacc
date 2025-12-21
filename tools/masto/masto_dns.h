#pragma once

#include "mc.h"
#include "mc_net.h"

// Resolves HOST to a single IPv6 address (AAAA). Returns 0 on success.
// Strategy:
// - If HOST looks like an IPv6 literal (contains ':'), parse it directly.
// - Otherwise, perform a minimal internal DNS AAAA lookup (IPv6-only).
int masto_resolve_aaaa(const char *host, struct mc_in6_addr *out);

// Connects to `addr:port` (IPv6) with a timeout in milliseconds.
// Returns a connected socket fd on success (>=0), or negative errno on failure.
mc_i64 masto_tcp_connect_v6(const struct mc_in6_addr *addr, mc_u16 port, mc_i32 timeout_ms);
