#pragma once

#include "mc.h"

// Extracts a JSON string field value by key, for the pattern: "key":"value".
// The search is best-effort and intended for Mastodon API responses.
//
// - Performs JSON unescaping (\\, \" etc)
// - Decodes ASCII-range \uXXXX escapes (e.g. \u003c -> '<')
// - Truncates safely if out_cap is too small
//
// Returns 0 on success, non-zero if not found or parse failure.
int masto_json_get_string_field(
	const char *json,
	mc_usize json_len,
	const char *key,
	char *out,
	mc_usize out_cap
);

// Finds a nested object field and returns a slice that starts at '{' and includes
// the matching '}'. Expects the pattern: "key":{...}
// Returns 0 on success.
int masto_json_find_object_field(
	const char *json,
	mc_usize json_len,
	const char *key,
	const char **out_obj,
	mc_usize *out_len
);

// Iterates over top-level objects within a JSON array.
// Starting at *pos, finds the next '{...}' and returns it; updates *pos.
// Returns 0 if an object was found, non-zero on end or failure.
int masto_json_next_object_in_array(
	const char *json,
	mc_usize json_len,
	mc_usize *pos,
	const char **out_obj,
	mc_usize *out_len
);

// Extracts an unsigned integer field value by key, for the pattern: "key":123.
// Whitespace between ':' and the number is tolerated.
// Returns 0 on success.
int masto_json_get_u64_field(
	const char *json,
	mc_usize json_len,
	const char *key,
	mc_u64 *out
);
