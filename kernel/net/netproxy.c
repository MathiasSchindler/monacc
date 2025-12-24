#include "kernel.h"
#include "net.h"

// Simple host-proxy protocol over COM2.
// Framing: [u32 magic][u8 op][u8 rsv0][u16 rsv1][u32 len][payload]
// Response op has high bit set (op|0x80).

#define NP_MAGIC 0x3158504eu /* 'NPX1' little-endian */

enum {
	NP_OP_PING = 0,
	NP_OP_SOCKET = 1,
	NP_OP_CONNECT = 2,
	NP_OP_SENDTO = 3,
	NP_OP_RECVFROM = 4,
	NP_OP_CLOSE = 5,
	NP_OP_SET_NONBLOCK = 6,
	NP_OP_POLL = 7,
};

static int g_np_ready = 0;

static void np_write_u32(uint32_t v) {
	serial2_putc((char)(v & 0xffu));
	serial2_putc((char)((v >> 8) & 0xffu));
	serial2_putc((char)((v >> 16) & 0xffu));
	serial2_putc((char)((v >> 24) & 0xffu));
}

static void np_write_u16(uint16_t v) {
	serial2_putc((char)(v & 0xffu));
	serial2_putc((char)((v >> 8) & 0xffu));
}

static uint32_t np_read_u32_block(void) {
	uint32_t v = 0;
	v |= (uint32_t)(uint8_t)serial2_getc();
	v |= (uint32_t)(uint8_t)serial2_getc() << 8;
	v |= (uint32_t)(uint8_t)serial2_getc() << 16;
	v |= (uint32_t)(uint8_t)serial2_getc() << 24;
	return v;
}

static uint16_t np_read_u16_block(void) {
	uint16_t v = 0;
	v |= (uint16_t)(uint8_t)serial2_getc();
	v |= (uint16_t)(uint8_t)serial2_getc() << 8;
	return v;
}

static int np_sync_and_read_hdr(uint8_t want_op, uint32_t *len_out) {
	uint32_t magic = np_read_u32_block();
	if (magic != NP_MAGIC) return 0;
	uint8_t op = (uint8_t)serial2_getc();
	(void)serial2_getc();
	(void)np_read_u16_block();
	uint32_t len = np_read_u32_block();
	if (op != (uint8_t)(want_op | 0x80u)) return 0;
	if (len_out) *len_out = len;
	return 1;
}

static void np_send_hdr(uint8_t op, uint32_t len) {
	np_write_u32(NP_MAGIC);
	serial2_putc((char)op);
	serial2_putc(0);
	np_write_u16(0);
	np_write_u32(len);
}

int netproxy_is_ready(void) {
	return g_np_ready;
}

int netproxy_ensure_ready(void) {
	if (g_np_ready) return 1;

	// Best-effort handshake: send PING and wait briefly for a response.
	np_send_hdr(NP_OP_PING, 0);

	// Wait for at most some number of iterations for the first byte.
	for (uint64_t spins = 0; spins < 2000000ull; spins++) {
		char c;
		if (serial2_try_getc(&c)) {
			// We consumed one byte; treat it as part of the framed response.
			// Reconstruct by treating that byte as the first byte of magic.
			uint32_t magic = (uint32_t)(uint8_t)c;
			magic |= (uint32_t)(uint8_t)serial2_getc() << 8;
			magic |= (uint32_t)(uint8_t)serial2_getc() << 16;
			magic |= (uint32_t)(uint8_t)serial2_getc() << 24;
			if (magic != NP_MAGIC) return 0;
			uint8_t op = (uint8_t)serial2_getc();
			(void)serial2_getc();
			(void)np_read_u16_block();
			uint32_t len = np_read_u32_block();
			// ignore payload
			for (uint32_t i = 0; i < len; i++) (void)serial2_getc();
			if (op == (uint8_t)(NP_OP_PING | 0x80u)) {
				g_np_ready = 1;
				return 1;
			}
			return 0;
		}
	}
	return 0;
}

static int64_t np_call_i64(uint8_t op, const void *payload, uint32_t payload_len, void *out_buf, uint32_t out_cap, uint32_t *out_len) {
	if (!netproxy_ensure_ready()) return -(int64_t)38; // -ENOSYS

	np_send_hdr(op, payload_len);
	if (payload_len && payload) {
		serial2_write(payload, payload_len);
	}

	uint32_t rlen = 0;
	if (!np_sync_and_read_hdr(op, &rlen)) return -(int64_t)71; // -EPROTO
	if (out_len) *out_len = rlen;
	if (rlen == 0) return 0;

	// First 8 bytes of payload are i64 result.
	uint64_t lo = np_read_u32_block();
	uint64_t hi = np_read_u32_block();
	uint64_t u = lo | (hi << 32);
	int64_t res = (int64_t)u;

	uint32_t remain = (rlen >= 8) ? (rlen - 8) : 0;
	uint32_t take = (remain < out_cap) ? remain : out_cap;
	if (take && out_buf) {
		serial2_read(out_buf, take);
	}
	for (uint32_t i = take; i < remain; i++) (void)serial2_getc();
	return res;
}

static int64_t np_read_i64_only(uint8_t op) {
	if (!netproxy_ensure_ready()) return -(int64_t)38; // -ENOSYS
	uint32_t rlen = 0;
	if (!np_sync_and_read_hdr(op, &rlen)) return -(int64_t)71; // -EPROTO
	if (rlen < 8) {
		for (uint32_t i = 0; i < rlen; i++) (void)serial2_getc();
		return -(int64_t)71;
	}
	uint64_t lo = np_read_u32_block();
	uint64_t hi = np_read_u32_block();
	uint64_t u = lo | (hi << 32);
	int64_t res = (int64_t)u;
	for (uint32_t i = 8; i < rlen; i++) (void)serial2_getc();
	return res;
}

int64_t netproxy_socket(uint32_t domain, uint32_t type, uint32_t proto) {
	uint32_t payload[3];
	payload[0] = domain;
	payload[1] = type;
	payload[2] = proto;
	return np_call_i64(NP_OP_SOCKET, payload, (uint32_t)sizeof(payload), 0, 0, 0);
}

int64_t netproxy_connect(uint32_t handle, const void *addr, uint32_t addrlen) {
	uint8_t buf[4 + 4 + 128];
	if (addrlen > 128u) return -(int64_t)22; // -EINVAL
	// handle
	buf[0] = (uint8_t)(handle & 0xffu);
	buf[1] = (uint8_t)((handle >> 8) & 0xffu);
	buf[2] = (uint8_t)((handle >> 16) & 0xffu);
	buf[3] = (uint8_t)((handle >> 24) & 0xffu);
	// addrlen
	buf[4] = (uint8_t)(addrlen & 0xffu);
	buf[5] = (uint8_t)((addrlen >> 8) & 0xffu);
	buf[6] = (uint8_t)((addrlen >> 16) & 0xffu);
	buf[7] = (uint8_t)((addrlen >> 24) & 0xffu);
	for (uint32_t i = 0; i < addrlen; i++) {
		buf[8 + i] = addr ? ((const uint8_t *)addr)[i] : 0;
	}
	return np_call_i64(NP_OP_CONNECT, buf, 8u + addrlen, 0, 0, 0);
}

int64_t netproxy_sendto(uint32_t handle, const void *buf, uint32_t len, uint32_t flags, const void *addr, uint32_t addrlen) {
	uint8_t hdr[4 + 4 + 4 + 4];
	// handle
	hdr[0] = (uint8_t)(handle & 0xffu);
	hdr[1] = (uint8_t)((handle >> 8) & 0xffu);
	hdr[2] = (uint8_t)((handle >> 16) & 0xffu);
	hdr[3] = (uint8_t)((handle >> 24) & 0xffu);
	// flags
	hdr[4] = (uint8_t)(flags & 0xffu);
	hdr[5] = (uint8_t)((flags >> 8) & 0xffu);
	hdr[6] = (uint8_t)((flags >> 16) & 0xffu);
	hdr[7] = (uint8_t)((flags >> 24) & 0xffu);
	// addrlen
	hdr[8] = (uint8_t)(addrlen & 0xffu);
	hdr[9] = (uint8_t)((addrlen >> 8) & 0xffu);
	hdr[10] = (uint8_t)((addrlen >> 16) & 0xffu);
	hdr[11] = (uint8_t)((addrlen >> 24) & 0xffu);
	// len
	hdr[12] = (uint8_t)(len & 0xffu);
	hdr[13] = (uint8_t)((len >> 8) & 0xffu);
	hdr[14] = (uint8_t)((len >> 16) & 0xffu);
	hdr[15] = (uint8_t)((len >> 24) & 0xffu);

	if (!netproxy_ensure_ready()) return -(int64_t)38;

	np_send_hdr(NP_OP_SENDTO, (uint32_t)(sizeof(hdr) + addrlen + len));
	serial2_write(hdr, (uint32_t)sizeof(hdr));
	if (addrlen && addr) serial2_write(addr, addrlen);
	if (len && buf) serial2_write(buf, len);

	return np_read_i64_only(NP_OP_SENDTO);
}

int64_t netproxy_recvfrom(uint32_t handle, void *buf, uint32_t len, uint32_t flags) {
	uint32_t payload[3];
	payload[0] = handle;
	payload[1] = flags;
	payload[2] = len;
	uint32_t out_len = 0;
	int64_t r = np_call_i64(NP_OP_RECVFROM, payload, (uint32_t)sizeof(payload), buf, len, &out_len);
	(void)out_len;
	return r;
}

int64_t netproxy_close(uint32_t handle) {
	uint32_t payload[1];
	payload[0] = handle;
	return np_call_i64(NP_OP_CLOSE, payload, (uint32_t)sizeof(payload), 0, 0, 0);
}

int64_t netproxy_set_nonblock(uint32_t handle, int nonblock) {
	uint32_t payload[2];
	payload[0] = handle;
	payload[1] = nonblock ? 1u : 0u;
	return np_call_i64(NP_OP_SET_NONBLOCK, payload, (uint32_t)sizeof(payload), 0, 0, 0);
}

int64_t netproxy_poll(const uint32_t *handles, const int16_t *events, int16_t *revents, uint32_t nfds, int32_t timeout_ms) {
	if (!handles || !events || !revents) return -(int64_t)14; // -EFAULT
	if (nfds == 0 || nfds > 16u) return -(int64_t)22; // -EINVAL

	uint8_t payload[4 + 16 * 8 + 4];
	uint32_t off = 0;
	// nfds
	payload[off + 0] = (uint8_t)(nfds & 0xffu);
	payload[off + 1] = (uint8_t)((nfds >> 8) & 0xffu);
	payload[off + 2] = (uint8_t)((nfds >> 16) & 0xffu);
	payload[off + 3] = (uint8_t)((nfds >> 24) & 0xffu);
	off += 4;

	for (uint32_t i = 0; i < nfds; i++) {
		uint32_t h = handles[i];
		int16_t ev = events[i];
		payload[off + 0] = (uint8_t)(h & 0xffu);
		payload[off + 1] = (uint8_t)((h >> 8) & 0xffu);
		payload[off + 2] = (uint8_t)((h >> 16) & 0xffu);
		payload[off + 3] = (uint8_t)((h >> 24) & 0xffu);
		payload[off + 4] = (uint8_t)(ev & 0xff);
		payload[off + 5] = (uint8_t)((ev >> 8) & 0xff);
		payload[off + 6] = 0;
		payload[off + 7] = 0;
		off += 8;
	}

	uint32_t t = (uint32_t)timeout_ms;
	payload[off + 0] = (uint8_t)(t & 0xffu);
	payload[off + 1] = (uint8_t)((t >> 8) & 0xffu);
	payload[off + 2] = (uint8_t)((t >> 16) & 0xffu);
	payload[off + 3] = (uint8_t)((t >> 24) & 0xffu);
	off += 4;

	uint8_t out[16 * 4];
	uint32_t out_len = 0;
	int64_t r = np_call_i64(NP_OP_POLL, payload, off, out, (uint32_t)sizeof(out), &out_len);
	if (r < 0) return r;

	// Response payload after i64 result is nfds * (i16 revents + pad)
	uint32_t need = nfds * 4u;
	if (out_len < 8u + need) {
		return -(int64_t)71;
	}
	for (uint32_t i = 0; i < nfds; i++) {
		uint32_t o = i * 4u;
		int16_t rev = (int16_t)((uint16_t)out[o + 0] | ((uint16_t)out[o + 1] << 8));
		revents[i] = rev;
	}
	return r;
}
