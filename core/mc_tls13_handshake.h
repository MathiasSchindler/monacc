#pragma once

#include "mc_types.h"

// Minimal TLS 1.3 handshake message encode/decode helpers.

#define MC_TLS13_HANDSHAKE_CLIENT_HELLO 1
#define MC_TLS13_HANDSHAKE_SERVER_HELLO 2

#define MC_TLS13_EXT_SERVER_NAME 0x0000
#define MC_TLS13_EXT_SUPPORTED_GROUPS 0x000a
#define MC_TLS13_EXT_SIGNATURE_ALGORITHMS 0x000d
#define MC_TLS13_EXT_SUPPORTED_VERSIONS 0x002b
#define MC_TLS13_EXT_PSK_KEY_EXCHANGE_MODES 0x002d
#define MC_TLS13_EXT_KEY_SHARE 0x0033
#define MC_TLS13_EXT_SESSION_TICKET 0x0023
#define MC_TLS13_EXT_RENEGOTIATION_INFO 0xff01
#define MC_TLS13_EXT_RECORD_SIZE_LIMIT 0x001c

#define MC_TLS13_GROUP_X25519 0x001d

struct mc_tls13_server_hello {
	mc_u16 legacy_version;
	mc_u8 random[32];
	mc_u8 legacy_session_id_echo_len;
	mc_u16 cipher_suite;
	mc_u8 legacy_compression_method;

	mc_u16 selected_version; // from supported_versions
	mc_u16 key_share_group;  // from key_share
	mc_u8 key_share[32];
	mc_u16 key_share_len;
};

// Builds the RFC 8448 Section 3 ClientHello (196 bytes) with provided random and key_share.
// Returns 0 on success, -1 on error.
int mc_tls13_build_client_hello_rfc8448_1rtt(
	const mc_u8 random32[32],
	const mc_u8 x25519_pub[32],
	mc_u8 *out, mc_usize out_cap, mc_usize *out_len
);

// Builds a minimal TLS 1.3 ClientHello suitable for real servers.
// Includes: server_name (SNI), supported_versions (TLS 1.3), supported_groups (x25519),
// signature_algorithms (RFC 8448 list), key_share (x25519), psk_key_exchange_modes (psk_dhe_ke).
// Returns 0 on success, -1 on error.
int mc_tls13_build_client_hello(
	const char *sni, mc_usize sni_len,
	const mc_u8 random32[32],
	const mc_u8 *legacy_session_id, mc_usize legacy_session_id_len,
	const mc_u8 x25519_pub[32],
	mc_u8 *out, mc_usize out_cap, mc_usize *out_len
);

// Parses a TLS 1.3 ServerHello handshake message (handshake header included).
// Only extracts supported_versions and key_share (x25519) extensions.
// Returns 0 on success, -1 on parse error.
int mc_tls13_parse_server_hello(
	const mc_u8 *msg, mc_usize msg_len,
	struct mc_tls13_server_hello *out
);
