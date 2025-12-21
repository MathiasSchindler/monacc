#include "masto_json.h"

static const char *memmem_lit(const char *hay, mc_usize hay_len, const char *needle) {
	mc_usize nlen = mc_strlen(needle);
	if (nlen == 0) return hay;
	if (hay_len < nlen) return MC_NULL;
	for (mc_usize i = 0; i + nlen <= hay_len; i++) {
		if (mc_memcmp(hay + i, needle, nlen) == 0) return hay + i;
	}
	return MC_NULL;
}

static int json_unescape_string(const char *s, mc_usize n, char *out, mc_usize out_cap) {
	mc_usize o = 0;
	mc_usize i = 0;
	while (i < n) {
		char c = s[i++];
		if (c == '\\') {
			if (i >= n) return 1;
			char e = s[i++];
			switch (e) {
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			case '/': c = '/'; break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'u': {
				if (i + 4u > n) return 1;
				mc_u32 v = 0;
				for (mc_usize k = 0; k < 4u; k++) {
					char h = s[i + k];
					mc_u32 d;
					if (h >= '0' && h <= '9') d = (mc_u32)(h - '0');
					else if (h >= 'a' && h <= 'f') d = (mc_u32)(h - 'a' + 10);
					else if (h >= 'A' && h <= 'F') d = (mc_u32)(h - 'A' + 10);
					else return 1;
					v = (v << 4) | d;
				}
				i += 4u;
				c = (v <= 0x7fu) ? (char)v : '?';
			} break;
			default:
				return 1;
			}
		}
		if (o + 1u >= out_cap) {
			// Truncate safely.
			out[out_cap - 1u] = 0;
			return 0;
		}
		out[o++] = c;
	}
	if (o < out_cap) out[o] = 0;
	return 0;
}

static int json_parse_u64_at(const char *s, mc_usize n, mc_u64 *out) {
	if (!out) return 1;
	mc_usize i = 0;
	while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) i++;
	if (i >= n) return 1;
	if (s[i] == '-') return 1;

	mc_u64 v = 0;
	int any = 0;
	for (; i < n; i++) {
		char c = s[i];
		if (c < '0' || c > '9') break;
		any = 1;
		mc_u64 nv = v * 10u + (mc_u64)(c - '0');
		if (nv < v) return 1;
		v = nv;
	}
	if (!any) return 1;
	*out = v;
	return 0;
}

int masto_json_get_string_field(
	const char *json,
	mc_usize json_len,
	const char *key,
	char *out,
	mc_usize out_cap
) {
	if (!json || !key || !*key || !out || out_cap == 0) return 1;
	out[0] = 0;

	// Build pattern: "key":"
	char pat[256];
	mc_usize kn = mc_strlen(key);
	if (kn + 4u >= sizeof(pat)) return 1;
	pat[0] = '"';
	mc_memcpy(pat + 1u, key, kn);
	pat[1u + kn] = '"';
	pat[2u + kn] = ':';
	pat[3u + kn] = '"';
	pat[4u + kn] = 0;

	const char *p = memmem_lit(json, json_len, pat);
	if (!p) return 1;
	p += 4u + kn; // points after opening quote of value

	const char *start = p;
	mc_usize i = (mc_usize)(start - json);
	int esc = 0;
	for (; i < json_len; i++) {
		char c = json[i];
		if (esc) {
			esc = 0;
			continue;
		}
		if (c == '\\') {
			esc = 1;
			continue;
		}
		if (c == '"') break;
	}
	if (i >= json_len) return 1;
	mc_usize raw_len = i - (mc_usize)(start - json);
	return json_unescape_string(start, raw_len, out, out_cap);
}

int masto_json_next_object_in_array(
	const char *json,
	mc_usize json_len,
	mc_usize *pos,
	const char **out_obj,
	mc_usize *out_len
) {
	if (!json || !pos || !out_obj || !out_len) return 1;
	mc_usize i = *pos;
	int in_str = 0;
	int esc = 0;
	int started = 0;
	mc_usize start = 0;
	mc_i32 depth = 0;

	for (; i < json_len; i++) {
		char c = json[i];
		if (in_str) {
			if (esc) {
				esc = 0;
				continue;
			}
			if (c == '\\') {
				esc = 1;
				continue;
			}
			if (c == '"') in_str = 0;
			continue;
		}
		if (c == '"') {
			in_str = 1;
			continue;
		}
		if (!started) {
			if (c == '{') {
				started = 1;
				start = i;
				depth = 1;
			}
			continue;
		}
		if (c == '{') {
			depth++;
			continue;
		}
		if (c == '}') {
			depth--;
			if (depth == 0) {
				*out_obj = json + start;
				*out_len = i - start + 1u;
				*pos = i + 1u;
				return 0;
			}
			continue;
		}
	}
	return 1;
}

int masto_json_find_object_field(
	const char *json,
	mc_usize json_len,
	const char *key,
	const char **out_obj,
	mc_usize *out_len
) {
	if (!json || !key || !*key || !out_obj || !out_len) return 1;

	// Looks for: "key":{
	char pat[256];
	mc_usize kn = mc_strlen(key);
	if (kn + 5u >= sizeof(pat)) return 1;
	pat[0] = '"';
	mc_memcpy(pat + 1u, key, kn);
	pat[1u + kn] = '"';
	pat[2u + kn] = ':';
	pat[3u + kn] = '{';
	pat[4u + kn] = 0;

	const char *p = memmem_lit(json, json_len, pat);
	if (!p) return 1;
	mc_usize start = (mc_usize)(p - json) + 3u + kn; // points to '{'

	int in_str = 0;
	int esc = 0;
	mc_i32 depth = 0;
	for (mc_usize i = start; i < json_len; i++) {
		char c = json[i];
		if (in_str) {
			if (esc) {
				esc = 0;
				continue;
			}
			if (c == '\\') {
				esc = 1;
				continue;
			}
			if (c == '"') in_str = 0;
			continue;
		}
		if (c == '"') {
			in_str = 1;
			continue;
		}
		if (c == '{') {
			depth++;
			continue;
		}
		if (c == '}') {
			depth--;
			if (depth == 0) {
				*out_obj = json + start;
				*out_len = i - start + 1u;
				return 0;
			}
			continue;
		}
	}
	return 1;
}

int masto_json_get_u64_field(
	const char *json,
	mc_usize json_len,
	const char *key,
	mc_u64 *out
) {
	if (!json || !key || !*key || !out) return 1;
	*out = 0;

	// Build pattern: "key":
	char pat[256];
	mc_usize kn = mc_strlen(key);
	if (kn + 3u >= sizeof(pat)) return 1;
	pat[0] = '"';
	mc_memcpy(pat + 1u, key, kn);
	pat[1u + kn] = '"';
	pat[2u + kn] = ':';
	pat[3u + kn] = 0;

	const char *p = memmem_lit(json, json_len, pat);
	if (!p) return 1;
	// p points at '"', advance to after ':'
	const char *v = p + 2u + kn + 1u;
	mc_usize off = (mc_usize)(v - json);
	if (off >= json_len) return 1;
	return json_parse_u64_at(v, json_len - off, out);
}
