#include "mc.h"
#include "mc_tls13_handshake.h"

struct wbuf {
	mc_u8 *p;
	mc_usize cap;
	mc_usize len;
};

static int wb_init(struct wbuf *b, mc_u8 *p, mc_usize cap) {
	if (!b || !p || cap == 0) return -1;
	b->p = p;
	b->cap = cap;
	b->len = 0;
	return 0;
}

static int wb_put_u8(struct wbuf *b, mc_u8 v) {
	if (!b || b->len + 1u > b->cap) return -1;
	b->p[b->len++] = v;
	return 0;
}

static int wb_put_u16(struct wbuf *b, mc_u16 v) {
	if (!b || b->len + 2u > b->cap) return -1;
	b->p[b->len++] = (mc_u8)(v >> 8);
	b->p[b->len++] = (mc_u8)(v >> 0);
	return 0;
}

static int wb_put_u24(struct wbuf *b, mc_u32 v) {
	if (!b || b->len + 3u > b->cap) return -1;
	b->p[b->len++] = (mc_u8)(v >> 16);
	b->p[b->len++] = (mc_u8)(v >> 8);
	b->p[b->len++] = (mc_u8)(v >> 0);
	return 0;
}

static int wb_put_bytes(struct wbuf *b, const mc_u8 *p, mc_usize n) {
	if (!b) return -1;
	if (!p && n) return -1;
	if (b->len + n > b->cap) return -1;
	if (n) mc_memcpy(b->p + b->len, p, n);
	b->len += n;
	return 0;
}

static int wb_put_cstr(struct wbuf *b, const char *s) {
	if (!s) return -1;
	mc_usize n = mc_strlen(s);
	return wb_put_bytes(b, (const mc_u8 *)s, n);
}

static void wb_patch_u16_at(struct wbuf *b, mc_usize off, mc_u16 v) {
	if (!b) return;
	if (off + 2u > b->cap) return;
	b->p[off + 0u] = (mc_u8)(v >> 8);
	b->p[off + 1u] = (mc_u8)(v >> 0);
}

static void wb_patch_u24_at(struct wbuf *b, mc_usize off, mc_u32 v) {
	if (!b) return;
	if (off + 3u > b->cap) return;
	b->p[off + 0u] = (mc_u8)(v >> 16);
	b->p[off + 1u] = (mc_u8)(v >> 8);
	b->p[off + 2u] = (mc_u8)(v >> 0);
}

// RFC 8448 ClientHello uses a fixed signature_algorithms list (15 pairs).
static const mc_u8 *rfc8448_sig_algs_ptr(void) {
	return (const mc_u8 *)
		"\x04\x03\x05\x03\x06\x03\x02\x03\x08\x04\x08\x05\x08\x06\x04\x01"
		"\x05\x01\x06\x01\x02\x01\x04\x02\x05\x02\x06\x02\x02\x02";
}

#define RFC8448_SIG_ALGS_LEN 30u

int mc_tls13_build_client_hello(
	const char *sni, mc_usize sni_len,
	const mc_u8 random32[32],
	const mc_u8 *legacy_session_id, mc_usize legacy_session_id_len,
	const mc_u8 x25519_pub[32],
	mc_u8 *out, mc_usize out_cap, mc_usize *out_len
) {
	if (!out || !out_len) return -1;
	if (!sni || sni_len == 0) return -1;
	if (!random32 || !x25519_pub) return -1;
	if (!legacy_session_id && legacy_session_id_len) return -1;
	if (legacy_session_id_len > 32u) return -1;
	if (sni_len > 0xffffu) return -1;

	struct wbuf b;
	if (wb_init(&b, out, out_cap) != 0) return -1;

	// Handshake header
	if (wb_put_u8(&b, MC_TLS13_HANDSHAKE_CLIENT_HELLO) != 0) return -1;
	mc_usize hs_len_off = b.len;
	if (wb_put_u24(&b, 0) != 0) return -1;

	// legacy_version
	if (wb_put_u16(&b, 0x0303) != 0) return -1;
	// random
	if (wb_put_bytes(&b, random32, 32) != 0) return -1;
	// legacy_session_id
	if (wb_put_u8(&b, (mc_u8)legacy_session_id_len) != 0) return -1;
	if (wb_put_bytes(&b, legacy_session_id, legacy_session_id_len) != 0) return -1;

	// cipher_suites: only TLS_AES_128_GCM_SHA256 (0x1301)
	if (wb_put_u16(&b, 2) != 0) return -1;
	if (wb_put_u16(&b, 0x1301) != 0) return -1;

	// legacy_compression_methods: length=1, method=0
	if (wb_put_u8(&b, 1) != 0) return -1;
	if (wb_put_u8(&b, 0) != 0) return -1;

	// extensions (patch length later)
	mc_usize exts_len_off = b.len;
	if (wb_put_u16(&b, 0) != 0) return -1;
	mc_usize exts_start = b.len;

	// server_name (type 0)
	if (wb_put_u16(&b, MC_TLS13_EXT_SERVER_NAME) != 0) return -1;
	mc_usize sn_len_off = b.len;
	if (wb_put_u16(&b, 0) != 0) return -1;
	mc_usize sn_start = b.len;
	// ServerNameList length
	if (wb_put_u16(&b, 0) != 0) return -1;
	mc_usize snlist_start = b.len;
	// name_type + name
	if (wb_put_u8(&b, 0) != 0) return -1;
	// host_name length
	if (wb_put_u16(&b, (mc_u16)sni_len) != 0) return -1;
	if (wb_put_bytes(&b, (const mc_u8 *)sni, sni_len) != 0) return -1;
	// patch ServerNameList length
	wb_patch_u16_at(&b, sn_start, (mc_u16)(b.len - snlist_start));
	// patch extension length
	wb_patch_u16_at(&b, sn_len_off, (mc_u16)(b.len - sn_start));

	// supported_groups (0x000a): just x25519
	if (wb_put_u16(&b, MC_TLS13_EXT_SUPPORTED_GROUPS) != 0) return -1;
	if (wb_put_u16(&b, 4) != 0) return -1; // ext len
	if (wb_put_u16(&b, 2) != 0) return -1; // list len
	if (wb_put_u16(&b, MC_TLS13_GROUP_X25519) != 0) return -1;

	// key_share (0x0033): x25519
	if (wb_put_u16(&b, MC_TLS13_EXT_KEY_SHARE) != 0) return -1;
	if (wb_put_u16(&b, 0x0026) != 0) return -1; // ext len 38
	if (wb_put_u16(&b, 0x0024) != 0) return -1; // client_shares len 36
	if (wb_put_u16(&b, MC_TLS13_GROUP_X25519) != 0) return -1;
	if (wb_put_u16(&b, 0x0020) != 0) return -1; // key_exchange len 32
	if (wb_put_bytes(&b, x25519_pub, 32) != 0) return -1;

	// supported_versions (0x002b): TLS 1.3
	if (wb_put_u16(&b, MC_TLS13_EXT_SUPPORTED_VERSIONS) != 0) return -1;
	if (wb_put_u16(&b, 3) != 0) return -1;
	if (wb_put_u8(&b, 2) != 0) return -1;
	if (wb_put_u16(&b, 0x0304) != 0) return -1;

	// signature_algorithms (0x000d): RFC 8448 list
	if (wb_put_u16(&b, MC_TLS13_EXT_SIGNATURE_ALGORITHMS) != 0) return -1;
	if (wb_put_u16(&b, 0x0020) != 0) return -1;
	if (wb_put_u16(&b, 0x001e) != 0) return -1;
	if (wb_put_bytes(&b, rfc8448_sig_algs_ptr(), RFC8448_SIG_ALGS_LEN) != 0) return -1;

	// psk_key_exchange_modes (0x002d): psk_dhe_ke (1)
	if (wb_put_u16(&b, MC_TLS13_EXT_PSK_KEY_EXCHANGE_MODES) != 0) return -1;
	if (wb_put_u16(&b, 2) != 0) return -1;
	if (wb_put_u8(&b, 1) != 0) return -1;
	if (wb_put_u8(&b, 1) != 0) return -1;

	mc_usize exts_len = b.len - exts_start;
	if (exts_len > 0xffffu) return -1;
	wb_patch_u16_at(&b, exts_len_off, (mc_u16)exts_len);

	mc_usize hs_len = b.len - (hs_len_off + 3u);
	if (hs_len > 0xffffffu) return -1;
	wb_patch_u24_at(&b, hs_len_off, (mc_u32)hs_len);

	*out_len = b.len;
	return 0;
}

int mc_tls13_build_client_hello_rfc8448_1rtt(
	const mc_u8 random32[32],
	const mc_u8 x25519_pub[32],
	mc_u8 *out, mc_usize out_cap, mc_usize *out_len
) {
	if (!out || !out_len) return -1;
	if (!random32 || !x25519_pub) return -1;

	struct wbuf b;
	if (wb_init(&b, out, out_cap) != 0) return -1;

	// Handshake header
	if (wb_put_u8(&b, MC_TLS13_HANDSHAKE_CLIENT_HELLO) != 0) return -1;
	mc_usize hs_len_off = b.len;
	if (wb_put_u24(&b, 0) != 0) return -1;

	// legacy_version
	if (wb_put_u16(&b, 0x0303) != 0) return -1;
	// random
	if (wb_put_bytes(&b, random32, 32) != 0) return -1;
	// legacy_session_id (empty in RFC 8448 trace)
	if (wb_put_u8(&b, 0) != 0) return -1;

	// cipher_suites
	// length = 6, suites: 1301, 1303, 1302
	if (wb_put_u16(&b, 6) != 0) return -1;
	if (wb_put_u16(&b, 0x1301) != 0) return -1;
	if (wb_put_u16(&b, 0x1303) != 0) return -1;
	if (wb_put_u16(&b, 0x1302) != 0) return -1;

	// legacy_compression_methods: length=1, method=0
	if (wb_put_u8(&b, 1) != 0) return -1;
	if (wb_put_u8(&b, 0) != 0) return -1;

	// extensions (patch length later)
	mc_usize exts_len_off = b.len;
	if (wb_put_u16(&b, 0) != 0) return -1;
	mc_usize exts_start = b.len;

	// server_name (type 0)
	if (wb_put_u16(&b, MC_TLS13_EXT_SERVER_NAME) != 0) return -1;
	mc_usize sn_len_off = b.len;
	if (wb_put_u16(&b, 0) != 0) return -1;
	mc_usize sn_start = b.len;
	// ServerNameList length
	if (wb_put_u16(&b, 0) != 0) return -1;
	mc_usize snlist_start = b.len;
	// name_type + name
	if (wb_put_u8(&b, 0) != 0) return -1;
	// host_name length
	if (wb_put_u16(&b, 6) != 0) return -1;
	if (wb_put_cstr(&b, "server") != 0) return -1;
	// patch ServerNameList length
	wb_patch_u16_at(&b, sn_start, (mc_u16)(b.len - snlist_start));
	// patch extension length
	wb_patch_u16_at(&b, sn_len_off, (mc_u16)(b.len - sn_start));

	// renegotiation_info (ff01), length 1, value 00
	if (wb_put_u16(&b, MC_TLS13_EXT_RENEGOTIATION_INFO) != 0) return -1;
	if (wb_put_u16(&b, 1) != 0) return -1;
	if (wb_put_u8(&b, 0) != 0) return -1;

	// supported_groups (0x000a)
	if (wb_put_u16(&b, MC_TLS13_EXT_SUPPORTED_GROUPS) != 0) return -1;
	if (wb_put_u16(&b, 0x0014) != 0) return -1; // ext len 20
	if (wb_put_u16(&b, 0x0012) != 0) return -1; // list len 18
	// groups list
	if (wb_put_u16(&b, 0x001d) != 0) return -1;
	if (wb_put_u16(&b, 0x0017) != 0) return -1;
	if (wb_put_u16(&b, 0x0018) != 0) return -1;
	if (wb_put_u16(&b, 0x0019) != 0) return -1;
	if (wb_put_u16(&b, 0x0100) != 0) return -1;
	if (wb_put_u16(&b, 0x0101) != 0) return -1;
	if (wb_put_u16(&b, 0x0102) != 0) return -1;
	if (wb_put_u16(&b, 0x0103) != 0) return -1;
	if (wb_put_u16(&b, 0x0104) != 0) return -1;

	// session_ticket (0x0023) empty
	if (wb_put_u16(&b, MC_TLS13_EXT_SESSION_TICKET) != 0) return -1;
	if (wb_put_u16(&b, 0) != 0) return -1;

	// key_share (0x0033)
	if (wb_put_u16(&b, MC_TLS13_EXT_KEY_SHARE) != 0) return -1;
	if (wb_put_u16(&b, 0x0026) != 0) return -1; // ext len 38
	if (wb_put_u16(&b, 0x0024) != 0) return -1; // client_shares len 36
	if (wb_put_u16(&b, MC_TLS13_GROUP_X25519) != 0) return -1;
	if (wb_put_u16(&b, 0x0020) != 0) return -1; // key_exchange len 32
	if (wb_put_bytes(&b, x25519_pub, 32) != 0) return -1;

	// supported_versions (0x002b)
	if (wb_put_u16(&b, MC_TLS13_EXT_SUPPORTED_VERSIONS) != 0) return -1;
	if (wb_put_u16(&b, 3) != 0) return -1;
	if (wb_put_u8(&b, 2) != 0) return -1;
	if (wb_put_u16(&b, 0x0304) != 0) return -1;

	// signature_algorithms (0x000d)
	if (wb_put_u16(&b, MC_TLS13_EXT_SIGNATURE_ALGORITHMS) != 0) return -1;
	if (wb_put_u16(&b, 0x0020) != 0) return -1;
	if (wb_put_u16(&b, 0x001e) != 0) return -1;
	if (wb_put_bytes(&b, rfc8448_sig_algs_ptr(), RFC8448_SIG_ALGS_LEN) != 0) return -1;

	// psk_key_exchange_modes (0x002d)
	if (wb_put_u16(&b, MC_TLS13_EXT_PSK_KEY_EXCHANGE_MODES) != 0) return -1;
	if (wb_put_u16(&b, 2) != 0) return -1;
	if (wb_put_u8(&b, 1) != 0) return -1;
	if (wb_put_u8(&b, 1) != 0) return -1;

	// record_size_limit (0x001c)
	if (wb_put_u16(&b, MC_TLS13_EXT_RECORD_SIZE_LIMIT) != 0) return -1;
	if (wb_put_u16(&b, 2) != 0) return -1;
	if (wb_put_u16(&b, 0x4001) != 0) return -1;

	mc_usize exts_len = b.len - exts_start;
	if (exts_len > 0xffffu) return -1;
	wb_patch_u16_at(&b, exts_len_off, (mc_u16)exts_len);

	mc_usize hs_len = b.len - (hs_len_off + 3u);
	if (hs_len > 0xffffffu) return -1;
	wb_patch_u24_at(&b, hs_len_off, (mc_u32)hs_len);

	*out_len = b.len;
	return 0;
}

struct rbuf {
	const mc_u8 *p;
	mc_usize len;
	mc_usize off;
};

static int rb_init(struct rbuf *r, const mc_u8 *p, mc_usize len) {
	if (!r || (!p && len)) return -1;
	r->p = p;
	r->len = len;
	r->off = 0;
	return 0;
}

static int rb_need(struct rbuf *r, mc_usize n) {
	if (!r) return -1;
	return (r->off + n <= r->len) ? 0 : -1;
}

static int rb_get_u8(struct rbuf *r, mc_u8 *out) {
	if (!out) return -1;
	if (rb_need(r, 1) != 0) return -1;
	*out = r->p[r->off++];
	return 0;
}

static int rb_get_u16(struct rbuf *r, mc_u16 *out) {
	if (!out) return -1;
	if (rb_need(r, 2) != 0) return -1;
	mc_u16 v = (mc_u16)((mc_u16)r->p[r->off] << 8);
	v |= (mc_u16)r->p[r->off + 1u];
	r->off += 2;
	*out = v;
	return 0;
}

static int rb_get_u24(struct rbuf *r, mc_u32 *out) {
	if (!out) return -1;
	if (rb_need(r, 3) != 0) return -1;
	mc_u32 v = 0;
	v |= ((mc_u32)r->p[r->off + 0u] << 16);
	v |= ((mc_u32)r->p[r->off + 1u] << 8);
	v |= ((mc_u32)r->p[r->off + 2u] << 0);
	r->off += 3;
	*out = v;
	return 0;
}

static int rb_get_bytes(struct rbuf *r, mc_u8 *out, mc_usize n) {
	if (!out && n) return -1;
	if (rb_need(r, n) != 0) return -1;
	if (n) mc_memcpy(out, r->p + r->off, n);
	r->off += n;
	return 0;
}

static int rb_skip(struct rbuf *r, mc_usize n) {
	if (rb_need(r, n) != 0) return -1;
	r->off += n;
	return 0;
}

int mc_tls13_parse_server_hello(
	const mc_u8 *msg, mc_usize msg_len,
	struct mc_tls13_server_hello *out
) {
	if (!msg || !out) return -1;
	mc_memset(out, 0, sizeof(*out));

	struct rbuf r;
	if (rb_init(&r, msg, msg_len) != 0) return -1;

	mc_u8 hs_type = 0;
	mc_u32 hs_len = 0;
	if (rb_get_u8(&r, &hs_type) != 0) return -1;
	if (rb_get_u24(&r, &hs_len) != 0) return -1;
	if (hs_type != MC_TLS13_HANDSHAKE_SERVER_HELLO) return -1;
	if (r.off + (mc_usize)hs_len != r.len) return -1;

	if (rb_get_u16(&r, &out->legacy_version) != 0) return -1;
	if (rb_get_bytes(&r, out->random, 32) != 0) return -1;
	if (rb_get_u8(&r, &out->legacy_session_id_echo_len) != 0) return -1;
	if (rb_skip(&r, (mc_usize)out->legacy_session_id_echo_len) != 0) return -1;
	if (rb_get_u16(&r, &out->cipher_suite) != 0) return -1;
	if (rb_get_u8(&r, &out->legacy_compression_method) != 0) return -1;

	mc_u16 exts_len = 0;
	if (rb_get_u16(&r, &exts_len) != 0) return -1;
	if (rb_need(&r, exts_len) != 0) return -1;
	mc_usize exts_end = r.off + (mc_usize)exts_len;

	while (r.off < exts_end) {
		mc_u16 ext_type = 0;
		mc_u16 ext_len = 0;
		if (rb_get_u16(&r, &ext_type) != 0) return -1;
		if (rb_get_u16(&r, &ext_len) != 0) return -1;
		if (rb_need(&r, ext_len) != 0) return -1;

		mc_usize ext_start = r.off;
		if (ext_type == MC_TLS13_EXT_SUPPORTED_VERSIONS) {
			mc_u16 v = 0;
			if (ext_len != 2) return -1;
			if (rb_get_u16(&r, &v) != 0) return -1;
			out->selected_version = v;
		} else if (ext_type == MC_TLS13_EXT_KEY_SHARE) {
			mc_u16 group = 0;
			mc_u16 klen = 0;
			if (rb_get_u16(&r, &group) != 0) return -1;
			if (rb_get_u16(&r, &klen) != 0) return -1;
			if (klen > sizeof(out->key_share)) return -1;
			if (rb_get_bytes(&r, out->key_share, klen) != 0) return -1;
			out->key_share_group = group;
			out->key_share_len = klen;
		} else {
			if (rb_skip(&r, ext_len) != 0) return -1;
		}

		// Ensure we consumed exactly ext_len bytes.
		if (r.off != ext_start + (mc_usize)ext_len) return -1;
	}
	if (r.off != exts_end) return -1;

	return 0;
}
