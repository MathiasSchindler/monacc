#include "masto_url.h"

static char hex_up(mc_u8 v) {
	v &= 0x0f;
	return (v < 10) ? (char)('0' + v) : (char)('A' + (v - 10));
}

int masto_urlencode_form(const char *in, char *out, mc_usize out_cap) {
	if (!out || out_cap == 0) return 1;
	out[0] = 0;
	if (!in) return 0;

	mc_usize o = 0;
	for (mc_usize i = 0; in[i] != 0; i++) {
		mc_u8 c = (mc_u8)in[i];
		int safe =
			(c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~';
		if (c == ' ') {
			if (o + 1u >= out_cap) return 1;
			out[o++] = '+';
			continue;
		}
		if (safe) {
			if (o + 1u >= out_cap) return 1;
			out[o++] = (char)c;
			continue;
		}
		if (o + 3u >= out_cap) return 1;
		out[o++] = '%';
		out[o++] = hex_up((mc_u8)(c >> 4));
		out[o++] = hex_up((mc_u8)(c & 0x0f));
	}
	if (o >= out_cap) return 1;
	out[o] = 0;
	return 0;
}
