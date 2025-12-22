#include "mc.h"

struct expr_val {
	int is_num;
	mc_i64 num;
	const char *str;
	mc_usize len;
};

static const char *expr_g_argv0;
static int expr_g_argc;
static char **expr_g_argv;
static int expr_g_pos;

static int expr_token_is(const char *t, const char *lit) {
	return t && lit && mc_streq(t, lit);
}

static const char *expr_peek(void) {
	if (expr_g_pos >= expr_g_argc) return 0;
	return expr_g_argv[expr_g_pos];
}

static const char *expr_take(void) {
	const char *t = expr_peek();
	if (t) expr_g_pos++;
	return t;
}

static int expr_is_i64(const char *s, mc_i64 *out) {
	mc_i64 v = 0;
	if (mc_parse_i64_dec(s, &v) == 0) {
		if (out) *out = v;
		return 1;
	}
	return 0;
}

static int expr_strcmp(const char *a, mc_usize an, const char *b, mc_usize bn) {
	mc_usize n = (an < bn) ? an : bn;
	for (mc_usize i = 0; i < n; i++) {
		mc_u8 ac = (mc_u8)a[i];
		mc_u8 bc = (mc_u8)b[i];
		if (ac < bc) return -1;
		if (ac > bc) return 1;
	}
	if (an < bn) return -1;
	if (an > bn) return 1;
	return 0;
}

static int expr_truthy(const struct expr_val *v) {
	if (!v) return 0;
	if (v->is_num) return v->num != 0;
	if (v->len == 0) return 0;
	if (v->len == 1 && v->str[0] == '0') return 0;
	return 1;
}

static MC_NORETURN void expr_usage(const char *argv0) {
	mc_die_usage(argv0, "expr EXPR");
}

static void expr_val_set(struct expr_val *dst, int is_num, mc_i64 num, const char *str, mc_usize len) {
	if (!dst) return;
	dst->is_num = is_num;
	dst->num = num;
	dst->str = str;
	dst->len = len;
}

static void expr_val_copy(struct expr_val *dst, const struct expr_val *src) {
	if (!dst || !src) return;
	dst->is_num = src->is_num;
	dst->num = src->num;
	dst->str = src->str;
	dst->len = src->len;
}

static void expr_val_from_token(const char *t, struct expr_val *out) {
	const char *s = t ? t : "";
	mc_usize n = mc_strlen(s);
	mc_i64 num = 0;
	int is_num = 0;
	if (t && expr_is_i64(t, &num)) {
		is_num = 1;
	}
	expr_val_set(out, is_num, num, s, n);
}

static mc_i64 expr_as_i64(const char *argv0, const struct expr_val *v) {
	if (v && v->is_num) return v->num;
	mc_i64 n = 0;
	if (v && expr_is_i64(v->str, &n)) return n;
	expr_usage(argv0);
	return 0;
}

static void expr_parse_or(const char *argv0, struct expr_val *out);

static void expr_parse_primary(const char *argv0, struct expr_val *out) {
	const char *t = expr_peek();
	if (!t) expr_usage(argv0);
	if (expr_token_is(t, "(")) {
		(void)expr_take();
		struct expr_val v;
		expr_val_set(&v, 0, 0, "", 0);
		expr_parse_or(argv0, &v);
		const char *c = expr_take();
		if (!expr_token_is(c, ")")) expr_usage(argv0);
		expr_val_copy(out, &v);
		return;
	}
	(void)expr_take();
	expr_val_from_token(t, out);
}

static void expr_parse_mul(const char *argv0, struct expr_val *out) {
	struct expr_val left;
	expr_val_set(&left, 0, 0, "", 0);
	expr_parse_primary(argv0, &left);
	for (;;) {
		const char *op = expr_peek();
		if (!op) break;
		if (!expr_token_is(op, "*") && !expr_token_is(op, "/") && !expr_token_is(op, "%")) break;
		(void)expr_take();
		mc_i64 a = expr_as_i64(argv0, &left);
		struct expr_val right;
		expr_val_set(&right, 0, 0, "", 0);
		expr_parse_primary(argv0, &right);
		mc_i64 b = expr_as_i64(argv0, &right);
		struct expr_val tmp;
		expr_val_set(&tmp, 1, 0, "", 0);
		if (expr_token_is(op, "*")) {
			tmp.num = a * b;
		} else if (expr_token_is(op, "/")) {
			if (b == 0) expr_usage(argv0);
			tmp.num = a / b;
		} else {
			if (b == 0) expr_usage(argv0);
			tmp.num = a % b;
		}
		expr_val_copy(&left, &tmp);
	}
	expr_val_copy(out, &left);
}

static void expr_parse_add(const char *argv0, struct expr_val *out) {
	struct expr_val left;
	expr_val_set(&left, 0, 0, "", 0);
	expr_parse_mul(argv0, &left);
	for (;;) {
		const char *op = expr_peek();
		if (!op) break;
		if (!expr_token_is(op, "+") && !expr_token_is(op, "-")) break;
		(void)expr_take();
		mc_i64 a = expr_as_i64(argv0, &left);
		struct expr_val right;
		expr_val_set(&right, 0, 0, "", 0);
		expr_parse_mul(argv0, &right);
		mc_i64 b = expr_as_i64(argv0, &right);
		struct expr_val tmp;
		expr_val_set(&tmp, 1, 0, "", 0);
		tmp.num = expr_token_is(op, "+") ? (a + b) : (a - b);
		expr_val_copy(&left, &tmp);
	}
	expr_val_copy(out, &left);
}

static void expr_parse_cmp(const char *argv0, struct expr_val *out) {
	struct expr_val left;
	expr_val_set(&left, 0, 0, "", 0);
	expr_parse_add(argv0, &left);
	for (;;) {
		const char *op = expr_peek();
		if (!op) break;
		int is_cmp = expr_token_is(op, "=") || expr_token_is(op, "!=") || expr_token_is(op, "<") || expr_token_is(op, "<=") ||
			expr_token_is(op, ">") || expr_token_is(op, ">=");
		if (!is_cmp) break;
		(void)expr_take();
		struct expr_val right;
		expr_val_set(&right, 0, 0, "", 0);
		expr_parse_add(argv0, &right);

		int cmp = 0;
		mc_i64 an = 0;
		mc_i64 bn = 0;
		int an_ok = expr_is_i64(left.str, &an);
		int bn_ok = expr_is_i64(right.str, &bn);
		if (left.is_num || right.is_num || (an_ok && bn_ok)) {
			// Numeric compare if both parse as numbers.
			if (!(an_ok && bn_ok)) {
				// If either side isn't a clean number, fall back to string compare.
				cmp = expr_strcmp(left.str, left.len, right.str, right.len);
			} else {
				if (an < bn) cmp = -1;
				else if (an > bn) cmp = 1;
				else cmp = 0;
			}
		} else {
			cmp = expr_strcmp(left.str, left.len, right.str, right.len);
		}

		int ok = 0;
		if (expr_token_is(op, "=")) ok = (cmp == 0);
		else if (expr_token_is(op, "!=")) ok = (cmp != 0);
		else if (expr_token_is(op, "<")) ok = (cmp < 0);
		else if (expr_token_is(op, "<=")) ok = (cmp <= 0);
		else if (expr_token_is(op, ">")) ok = (cmp > 0);
		else if (expr_token_is(op, ">=")) ok = (cmp >= 0);

		struct expr_val tmp;
		expr_val_set(&tmp, 1, ok ? 1 : 0, "", 0);
		expr_val_copy(&left, &tmp);
	}
	expr_val_copy(out, &left);
}

static void expr_parse_and(const char *argv0, struct expr_val *out) {
	struct expr_val left;
	expr_val_set(&left, 0, 0, "", 0);
	expr_parse_cmp(argv0, &left);
	for (;;) {
		const char *op = expr_peek();
		if (!expr_token_is(op, "&")) break;
		(void)expr_take();
		struct expr_val right;
		expr_val_set(&right, 0, 0, "", 0);
		expr_parse_cmp(argv0, &right);
		struct expr_val tmp;
		expr_val_set(&tmp, 1, (expr_truthy(&left) && expr_truthy(&right)) ? 1 : 0, "", 0);
		expr_val_copy(&left, &tmp);
	}
	expr_val_copy(out, &left);
}

static void expr_parse_or(const char *argv0, struct expr_val *out) {
	struct expr_val left;
	expr_val_set(&left, 0, 0, "", 0);
	expr_parse_and(argv0, &left);
	for (;;) {
		const char *op = expr_peek();
		if (!expr_token_is(op, "|")) break;
		(void)expr_take();
		struct expr_val right;
		expr_val_set(&right, 0, 0, "", 0);
		expr_parse_and(argv0, &right);
		if (!expr_truthy(&left)) {
			expr_val_copy(&left, &right);
		}
	}
	expr_val_copy(out, &left);
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "expr";
	if (argc < 2) expr_usage(argv0);

	expr_g_argv0 = argv0;
	expr_g_argc = argc;
	expr_g_argv = argv;
	expr_g_pos = 1;

	struct expr_val v;
	expr_val_set(&v, 0, 0, "", 0);
	expr_parse_or(argv0, &v);
	if (expr_peek() != 0) expr_usage(argv0);

	if (v.is_num) {
		mc_i64 w = mc_write_i64_dec(1, v.num);
		if (w < 0) mc_die_errno(argv0, "write", w);
	} else {
		mc_i64 w = mc_write_all(1, v.str, v.len);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}
	{
		char nl = '\n';
		mc_i64 w = mc_write_all(1, &nl, 1);
		if (w < 0) mc_die_errno(argv0, "write", w);
	}

	return expr_truthy(&v) ? 0 : 1;
}
