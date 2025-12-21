#include "mc.h"

#ifndef PROT_READ
#define PROT_READ 0x1
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif

#define MAX_FUNCS 512
#define STR_POOL 65536
#define TOKEN_POOL 50000
#define SIM_THRESHOLD 85u /* percent */
#define MIN_LEN_RATIO_NUM 1u
#define MIN_LEN_RATIO_DEN 2u /* 0.5 */

struct func_info {
	const char *name;
	const char *file;
	mc_u32 line;
	mc_u32 tok_start;
	mc_u32 tok_len;
	mc_u64 hash;
};

static struct func_info g_funcs[MAX_FUNCS];
static mc_u32 g_func_count;

static char g_str_pool[STR_POOL];
static mc_u32 g_str_used;

static mc_u32 g_tokens[TOKEN_POOL];
static mc_u32 g_tok_used;

static MC_INLINE mc_u64 fnv1a(mc_u64 h, mc_u8 b) {
	return (h ^ b) * 0x100000001b3ULL;
}

static const char *pool_copy(const char *s, mc_usize n) {
	if (g_str_used + n + 1 >= STR_POOL) {
		mc_write_str(2, "overlap: string pool exhausted\n");
		mc_exit(1);
	}
	mc_memcpy(&g_str_pool[g_str_used], s, n);
	g_str_pool[g_str_used + n] = 0;
	const char *out = &g_str_pool[g_str_used];
	g_str_used += (mc_u32)(n + 1);
	return out;
}

static int is_ident_start(mc_u8 c) {
	return (c == (mc_u8)'_' || (c >= (mc_u8)'A' && c <= (mc_u8)'Z') || (c >= (mc_u8)'a' && c <= (mc_u8)'z'));
}

static int is_ident(mc_u8 c) {
	return is_ident_start(c) || (c >= (mc_u8)'0' && c <= (mc_u8)'9');
}

static void skip_ws_comments(const char *buf, mc_usize len, mc_usize *pi) {
	mc_usize i = *pi;
	for (;;) {
		while (i < len && mc_is_space_ascii((mc_u8)buf[i])) i++;
		if (i + 1 < len && buf[i] == '/' && buf[i + 1] == '/') {
			i += 2;
			while (i < len && buf[i] != '\n') i++;
			continue;
		}
		if (i + 1 < len && buf[i] == '/' && buf[i + 1] == '*') {
			i += 2;
			while (i + 1 < len && !(buf[i] == '*' && buf[i + 1] == '/')) i++;
			if (i + 1 < len) i += 2;
			continue;
		}
		break;
	}
	*pi = i;
}

static mc_usize count_lines(const char *buf, mc_usize pos) {
	mc_usize n = 1;
	for (mc_usize i = 0; i < pos; i++) if (buf[i] == '\n') n++;
	return n;
}

static int parse_parens(const char *buf, mc_usize len, mc_usize *pi) {
	mc_usize i = *pi;
	if (i >= len || buf[i] != '(') return 0;
	mc_i32 depth = 0;
	for (; i < len; i++) {
		char c = buf[i];
		if (c == '"' || c == '\'') {
			char q = c;
			i++;
			while (i < len) {
				if (buf[i] == '\\') { i += 2; continue; }
				if (buf[i] == q) break;
				i++;
			}
			continue;
		}
		if (c == '/' && i + 1 < len && buf[i + 1] == '*') {
			i += 2;
			while (i + 1 < len && !(buf[i] == '*' && buf[i + 1] == '/')) i++;
			continue;
		}
		if (c == '/' && i + 1 < len && buf[i + 1] == '/') {
			i += 2;
			while (i < len && buf[i] != '\n') i++;
			continue;
		}
		if (c == '(') depth++;
		else if (c == ')') {
			depth--;
			if (depth == 0) { *pi = i + 1; return 1; }
		}
	}
	return 0;
}

static int parse_brace(const char *buf, mc_usize len, mc_usize start, mc_usize *out_end) {
	mc_i32 depth = 0;
	for (mc_usize i = start; i < len; i++) {
		char c = buf[i];
		if (c == '"' || c == '\'') {
			char q = c;
			i++;
			while (i < len) {
				if (buf[i] == '\\') { i += 2; continue; }
				if (buf[i] == q) break;
				i++;
			}
			continue;
		}
		if (c == '/' && i + 1 < len && buf[i + 1] == '*') {
			i += 2;
			while (i + 1 < len && !(buf[i] == '*' && buf[i + 1] == '/')) i++;
			continue;
		}
		if (c == '/' && i + 1 < len && buf[i + 1] == '/') {
			i += 2;
			while (i < len && buf[i] != '\n') i++;
			continue;
		}
		if (c == '{') depth++;
		else if (c == '}') {
			depth--;
			if (depth == 0) { *out_end = i + 1; return 1; }
		}
	}
	return 0;
}

static mc_u32 read_token(const char *buf, mc_usize len, mc_usize *pi) {
	mc_usize i = *pi;
	char c = buf[i];
	if (is_ident_start((mc_u8)c)) {
		while (i < len && is_ident((mc_u8)buf[i])) i++;
		*pi = i;
		return 1; // id
	}
	if ((c >= '0' && c <= '9') || c == '.') {
		i++;
		while (i < len && ((buf[i] >= '0' && buf[i] <= '9') || buf[i] == '.')) i++;
		*pi = i;
		return 2; // num
	}
	if (c == '"' || c == '\'') {
		char q = c;
		i++;
		while (i < len) {
			if (buf[i] == '\\') { i += 2; continue; }
			if (buf[i] == q) { i++; break; }
			i++;
		}
		*pi = i;
		return (q == '"') ? 3u : 4u;
	}
	if (i + 1 < len) {
		char n = buf[i + 1];
		if (c == '=' && n == '=') { *pi = i + 2; return 100u; }
		if (c == '!' && n == '=') { *pi = i + 2; return 101u; }
		if (c == '<' && n == '=') { *pi = i + 2; return 102u; }
		if (c == '>' && n == '=') { *pi = i + 2; return 103u; }
		if (c == '&' && n == '&') { *pi = i + 2; return 104u; }
		if (c == '|' && n == '|') { *pi = i + 2; return 105u; }
		if (c == '-' && n == '>') { *pi = i + 2; return 106u; }
	}
	*pi = i + 1;
	return 200u + (mc_u8)c;
}

static void tokenize_body(const char *buf, mc_usize len, mc_u32 *out_start, mc_u32 *out_len, mc_u64 *out_hash) {
	mc_usize i = 0;
	mc_u32 start = g_tok_used;
	mc_u64 h = 0xcbf29ce484222325ULL;

	while (i < len) {
		skip_ws_comments(buf, len, &i);
		if (i >= len) break;
		if (g_tok_used >= TOKEN_POOL) {
			mc_write_str(2, "overlap: token pool exhausted\n");
			mc_exit(1);
		}
		mc_u32 tok = read_token(buf, len, &i);
		g_tokens[g_tok_used++] = tok;
		h = fnv1a(h, (mc_u8)(tok & 0xFF));
		h = fnv1a(h, (mc_u8)((tok >> 8) & 0xFF));
		h = fnv1a(h, (mc_u8)((tok >> 16) & 0xFF));
		h = fnv1a(h, (mc_u8)((tok >> 24) & 0xFF));
	}

	*out_start = start;
	*out_len = g_tok_used - start;
	*out_hash = h;
}

static void add_function(const char *file, const char *name, mc_usize name_len, mc_u32 line, const char *body, mc_usize body_len) {
	if (g_func_count >= MAX_FUNCS) {
		mc_write_str(2, "overlap: too many functions\n");
		mc_exit(1);
	}
	const char *name_copy = pool_copy(name, name_len);
	const char *file_copy = pool_copy(file, mc_strlen(file));

	mc_u32 tok_start = 0, tok_len = 0;
	mc_u64 h = 0;
	tokenize_body(body, body_len, &tok_start, &tok_len, &h);

	struct func_info *f = &g_funcs[g_func_count++];
	f->name = name_copy;
	f->file = file_copy;
	f->line = line;
	f->tok_start = tok_start;
	f->tok_len = tok_len;
	f->hash = h;
}

static void scan_file(const char *path) {
	mc_i32 fd = (mc_i32)mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY, 0);
	if (fd < 0) return;

	struct mc_stat st;
	if (mc_sys_fstat(fd, &st) < 0 || st.st_size <= 0) { mc_sys_close(fd); return; }

	mc_usize sz = (mc_usize)st.st_size;
	mc_i64 map = mc_sys_mmap(MC_NULL, sz, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map < 0) { mc_sys_close(fd); return; }
	const char *buf = (const char *)map;

	mc_usize i = 0;
	while (i < sz) {
		skip_ws_comments(buf, sz, &i);
		if (i >= sz) break;
		if (!is_ident_start((mc_u8)buf[i])) { i++; continue; }
		mc_usize name_start = i;
		while (i < sz && is_ident((mc_u8)buf[i])) i++;
		mc_usize name_end = i;

		mc_usize after = i;
		skip_ws_comments(buf, sz, &after);
		if (after >= sz || buf[after] != '(') { i = after; continue; }
		if (!parse_parens(buf, sz, &after)) { i = after; continue; }
		skip_ws_comments(buf, sz, &after);
		if (after >= sz || buf[after] != '{') { i = after; continue; }
		mc_usize body_start = after;
		mc_usize body_end = 0;
		if (!parse_brace(buf, sz, body_start, &body_end)) { i = body_start + 1; continue; }

		mc_u32 line = (mc_u32)count_lines(buf, name_start);
		add_function(path, &buf[name_start], name_end - name_start, line, &buf[body_start], body_end - body_start);
		i = body_end;
	}

	mc_sys_munmap((void *)map, sz);
	mc_sys_close(fd);
}

static mc_u32 min_u32(mc_u32 a, mc_u32 b) { return a < b ? a : b; }
static mc_u32 max_u32(mc_u32 a, mc_u32 b) { return a > b ? a : b; }

static int same_tokens(const struct func_info *a, const struct func_info *b) {
	if (a->tok_len != b->tok_len) return 0;
	for (mc_u32 i = 0; i < a->tok_len; i++) {
		mc_u32 ia = a->tok_start + i;
		mc_u32 ib = b->tok_start + i;
		if (g_tokens[ia] != g_tokens[ib]) return 0;
	}
	return 1;
}

static void report_names(void) {
	mc_write_str(1, "Name collisions across files\n");
	mc_write_str(1, "----------------------------\n");
	int printed = 0;
	for (mc_u32 i = 0; i < g_func_count; i++) {
		for (mc_u32 j = i + 1; j < g_func_count; j++) {
			if (!mc_streq(g_funcs[i].name, g_funcs[j].name)) continue;
			if (mc_streq(g_funcs[i].file, g_funcs[j].file)) continue;
			printed = 1;
			mc_write_str(1, "  ");
			mc_write_str(1, g_funcs[i].name);
			mc_write_str(1, ": ");
			mc_write_str(1, g_funcs[i].file);
			mc_write_str(1, ", ");
			mc_write_str(1, g_funcs[j].file);
			mc_write_str(1, "\n");
		}
	}
	if (!printed) mc_write_str(1, "  (none)\n");
	mc_write_str(1, "  suggestion: consolidate shared helpers or rename for clarity.\n\n");
}

static void report_exact(void) {
	mc_write_str(1, "Exact body matches\n");
	mc_write_str(1, "------------------\n");
	int printed = 0;
	for (mc_u32 i = 0; i < g_func_count; i++) {
		for (mc_u32 j = i + 1; j < g_func_count; j++) {
			if (g_funcs[i].hash != g_funcs[j].hash) continue;
			if (!same_tokens(&g_funcs[i], &g_funcs[j])) continue;
			if (mc_streq(g_funcs[i].file, g_funcs[j].file)) continue;
			printed = 1;
			mc_write_str(1, "  hash ");
			mc_write_hex_u64(1, g_funcs[i].hash);
			mc_write_str(1, " shared by 2 functions:\n");
			mc_write_str(1, "    - ");
			mc_write_str(1, g_funcs[i].name);
			mc_write_str(1, " (");
			mc_write_str(1, g_funcs[i].file);
			mc_write_str(1, ":");
			mc_write_u64_dec(1, g_funcs[i].line);
			mc_write_str(1, ")\n");
			mc_write_str(1, "    - ");
			mc_write_str(1, g_funcs[j].name);
			mc_write_str(1, " (");
			mc_write_str(1, g_funcs[j].file);
			mc_write_str(1, ":");
			mc_write_u64_dec(1, g_funcs[j].line);
			mc_write_str(1, ")\n");
		}
	}
	if (!printed) mc_write_str(1, "  (none)\n");
	mc_write_str(1, "    suggestion: move shared logic into core/ or a common module.\n\n");
}

static mc_u32 similarity(const struct func_info *a, const struct func_info *b) {
	mc_u32 min_len = min_u32(a->tok_len, b->tok_len);
	mc_u32 max_len = max_u32(a->tok_len, b->tok_len);
	if (max_len == 0) return 0;
	if (min_len * MIN_LEN_RATIO_DEN < max_len * MIN_LEN_RATIO_NUM) return 0;
	mc_u32 eq = 0;
	for (mc_u32 i = 0; i < min_len; i++) {
		mc_u32 ia = a->tok_start + i;
		mc_u32 ib = b->tok_start + i;
		if (g_tokens[ia] == g_tokens[ib]) eq++;
	}
	return (mc_u32)((eq * 100u) / max_len);
}

static void report_similar(void) {
	mc_write_str(1, "Similar bodies\n");
	mc_write_str(1, "--------------\n");
	int printed = 0;
	for (mc_u32 i = 0; i < g_func_count; i++) {
		for (mc_u32 j = i + 1; j < g_func_count; j++) {
			if (mc_streq(g_funcs[i].file, g_funcs[j].file)) continue;
			if (g_funcs[i].hash == g_funcs[j].hash && same_tokens(&g_funcs[i], &g_funcs[j])) continue;
			mc_u32 sc = similarity(&g_funcs[i], &g_funcs[j]);
			if (sc < SIM_THRESHOLD) continue;
			printed = 1;
			mc_write_str(1, "  ");
			mc_write_u64_dec(1, sc);
			mc_write_str(1, ": ");
			mc_write_str(1, g_funcs[i].name);
			mc_write_str(1, " (");
			mc_write_str(1, g_funcs[i].file);
			mc_write_str(1, ":");
			mc_write_u64_dec(1, g_funcs[i].line);
			mc_write_str(1, ") <-> ");
			mc_write_str(1, g_funcs[j].name);
			mc_write_str(1, " (");
			mc_write_str(1, g_funcs[j].file);
			mc_write_str(1, ":");
			mc_write_u64_dec(1, g_funcs[j].line);
			mc_write_str(1, ")\n");
		}
	}
	if (!printed) mc_write_str(1, "  (none)\n");
	mc_write_str(1, "  suggestion: review similar pairs for potential refactors or shared utilities.\n\n");
}

static void usage(void) {
	mc_write_str(2, "usage: overlap FILE.c [FILE.c ...]\n");
}

mc_i32 main(mc_i32 argc, char **argv) {
	if (argc < 2) {
		usage();
		return 1;
	}
	for (mc_i32 i = 1; i < argc; i++) {
		scan_file(argv[i]);
	}

	mc_write_str(1, "monacc function overlap report (C)\n");
	mc_write_str(1, "Criteria: name collisions, identical bodies, similar token sequences.\n");
	mc_write_str(1, "Scanned ");
	mc_write_u64_dec(1, g_func_count);
	mc_write_str(1, " functions.\n\n");

	report_names();
	report_exact();
	report_similar();
	return 0;
}
