#include "masto_html.h"

mc_usize masto_html_strip(const char *in, mc_usize in_len, char *out, mc_usize out_cap) {
	mc_usize o = 0;
	int last_space = 1;
	if (!out || out_cap == 0) return 0;
	out[0] = 0;
	if (!in || in_len == 0) return 0;

	for (mc_usize i = 0; i < in_len; i++) {
		char c = in[i];
		if (c == '<') {
			// Convert common breaks to newlines.
			if (i + 3u < in_len && mc_memcmp(in + i, "<br", 3) == 0) {
				if (o + 1u < out_cap) out[o++] = '\n';
				last_space = 1;
			}
			if (i + 4u < in_len && mc_memcmp(in + i, "</p", 3) == 0) {
				if (o + 1u < out_cap) out[o++] = '\n';
				last_space = 1;
			}
			while (i < in_len && in[i] != '>') i++;
			continue;
		}

		if (c == '&') {
			const char *p = in + i;
			mc_usize rem = in_len - i;
			if (rem >= 5u && mc_memcmp(p, "&amp;", 5) == 0) {
				c = '&';
				i += 4u;
			} else if (rem >= 4u && mc_memcmp(p, "&lt;", 4) == 0) {
				c = '<';
				i += 3u;
			} else if (rem >= 4u && mc_memcmp(p, "&gt;", 4) == 0) {
				c = '>';
				i += 3u;
			} else if (rem >= 6u && mc_memcmp(p, "&quot;", 6) == 0) {
				c = '"';
				i += 5u;
			} else if (rem >= 5u && mc_memcmp(p, "&#39;", 5) == 0) {
				c = '\'';
				i += 4u;
			} else {
				while (i < in_len && in[i] != ';') i++;
				continue;
			}
		}

		if (c == '\r') continue;
		if (c == '\n' || c == '\t' || c == ' ') {
			if (!last_space) {
				if (o + 1u < out_cap) out[o++] = (c == '\n') ? '\n' : ' ';
				last_space = 1;
			}
			continue;
		}

		last_space = 0;
		if (o + 1u >= out_cap) break;
		out[o++] = c;
	}

	if (o < out_cap) out[o] = 0;
	return o;
}
