#include "mc.h"

struct expr_val {
	int is_num;
	mc_i64 num;
	const char *str;
	mc_usize len;
};

struct expr_parser {
	const char *argv0;
	int argc;
	char **argv;
	int pos;
};

static int expr_token_is(const char *t, const char *lit) {
	return t && lit && mc_streq(t, lit);
}

static const char *expr_peek(struct expr_parser *p) {
	if (!p) return 0;
	if (p->pos >= p->argc) return 0;
	return p->argv[p->pos];
}

static const char *expr_take(struct expr_parser *p) {
	const char *t = expr_peek(p);
	if (t) p->pos++;
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

static int expr_truthy(struct expr_val v) {
	if (v.is_num) return v.num != 0;
	if (v.len == 0) return 0;
	if (v.len == 1 && v.str[0] == '0') return 0;
	return 1;
}

static MC_NORETURN void expr_usage(const char *argv0) {
	mc_die_usage(argv0, "expr EXPR");
}

static struct expr_val expr_val_from_token(const char *t) {
	struct expr_val v = {0};
	v.str = t ? t : "";
	v.len = mc_strlen(v.str);
	mc_i64 n = 0;
	if (t && expr_is_i64(t, &n)) {
		v.is_num = 1;
		v.num = n;
	}
	return v;
}

static mc_i64 expr_as_i64(struct expr_parser *p, struct expr_val v) {
	if (v.is_num) return v.num;
	mc_i64 n = 0;
	if (expr_is_i64(v.str, &n)) return n;
	expr_usage(p->argv0);
	return 0;
}

static struct expr_val expr_parse_or(struct expr_parser *p);

static struct expr_val expr_parse_primary(struct expr_parser *p) {
	const char *t = expr_peek(p);
	if (!t) expr_usage(p->argv0);
	if (expr_token_is(t, "(")) {
		(void)expr_take(p);
		struct expr_val v = expr_parse_or(p);
		const char *c = expr_take(p);
		if (!expr_token_is(c, ")")) expr_usage(p->argv0);
		return v;
	}
	(void)expr_take(p);
	return expr_val_from_token(t);
}

static struct expr_val expr_parse_mul(struct expr_parser *p) {
	struct expr_val left = expr_parse_primary(p);
	for (;;) {
		const char *op = expr_peek(p);
		if (!op) break;
		if (!expr_token_is(op, "*") && !expr_token_is(op, "/") && !expr_token_is(op, "%")) break;
		(void)expr_take(p);
		mc_i64 a = expr_as_i64(p, left);
		struct expr_val right = expr_parse_primary(p);
		mc_i64 b = expr_as_i64(p, right);
		struct expr_val out = {0};
		out.is_num = 1;
		if (expr_token_is(op, "*")) {
			out.num = a * b;
		} else if (expr_token_is(op, "/")) {
			if (b == 0) expr_usage(p->argv0);
			out.num = a / b;
		} else {
			if (b == 0) expr_usage(p->argv0);
			out.num = a % b;
		}
		left = out;
	}
	return left;
}

static struct expr_val expr_parse_add(struct expr_parser *p) {
	struct expr_val left = expr_parse_mul(p);
	for (;;) {
		const char *op = expr_peek(p);
		if (!op) break;
		if (!expr_token_is(op, "+") && !expr_token_is(op, "-")) break;
		(void)expr_take(p);
		mc_i64 a = expr_as_i64(p, left);
		struct expr_val right = expr_parse_mul(p);
		mc_i64 b = expr_as_i64(p, right);
		struct expr_val out = {0};
		out.is_num = 1;
		out.num = expr_token_is(op, "+") ? (a + b) : (a - b);
		left = out;
	}
	return left;
}

static struct expr_val expr_parse_cmp(struct expr_parser *p) {
	struct expr_val left = expr_parse_add(p);
	for (;;) {
		const char *op = expr_peek(p);
		if (!op) break;
		int is_cmp = expr_token_is(op, "=") || expr_token_is(op, "!=") || expr_token_is(op, "<") || expr_token_is(op, "<=") ||
			expr_token_is(op, ">") || expr_token_is(op, ">=");
		if (!is_cmp) break;
		(void)expr_take(p);
		struct expr_val right = expr_parse_add(p);

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

		struct expr_val out = {0};
		out.is_num = 1;
		out.num = ok ? 1 : 0;
		left = out;
	}
	return left;
}

static struct expr_val expr_parse_and(struct expr_parser *p) {
	struct expr_val left = expr_parse_cmp(p);
	for (;;) {
		const char *op = expr_peek(p);
		if (!expr_token_is(op, "&")) break;
		(void)expr_take(p);
		struct expr_val right = expr_parse_cmp(p);
		struct expr_val out = {0};
		out.is_num = 1;
		out.num = (expr_truthy(left) && expr_truthy(right)) ? 1 : 0;
		left = out;
	}
	return left;
}

static struct expr_val expr_parse_or(struct expr_parser *p) {
	struct expr_val left = expr_parse_and(p);
	for (;;) {
		const char *op = expr_peek(p);
		if (!expr_token_is(op, "|")) break;
		(void)expr_take(p);
		struct expr_val right = expr_parse_and(p);
		left = expr_truthy(left) ? left : right;
	}
	return left;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "expr";
	if (argc < 2) expr_usage(argv0);

	struct expr_parser p = {0};
	p.argv0 = argv0;
	p.argc = argc;
	p.argv = argv;
	p.pos = 1;

	struct expr_val v = expr_parse_or(&p);
	if (expr_peek(&p) != 0) expr_usage(argv0);

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

	return expr_truthy(v) ? 0 : 1;
}
