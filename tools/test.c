#include "mc.h"

static int mc_ends_with(const char *s, const char *suffix) {
	if (!s || !suffix) {
		return 0;
	}
	mc_usize slen = mc_strlen(s);
	mc_usize tlen = mc_strlen(suffix);
	if (tlen > slen) {
		return 0;
	}
	const char *p = s + (slen - tlen);
	return mc_streq(p, suffix);
}

static int test_file_exists(const char *path) {
	struct mc_stat st;
	mc_i64 r = mc_sys_newfstatat(MC_AT_FDCWD, path, &st, 0);
	return (r >= 0);
}

static int test_file_kind(const char *path, mc_u32 kind) {
	struct mc_stat st;
	mc_i64 r = mc_sys_newfstatat(MC_AT_FDCWD, path, &st, 0);
	if (r < 0) {
		return 0;
	}
	return ((st.st_mode & MC_S_IFMT) == kind);
}

static int test_access(const char *path, mc_i32 mode) {
	mc_i64 r = mc_sys_faccessat(MC_AT_FDCWD, path, mode, 0);
	return (r >= 0);
}

static int eval_unary(const char *op, const char *arg, const char *argv0, int bracket_mode) {
	(void)argv0;
	(void)bracket_mode;
	if (mc_streq(op, "-e")) {
		return test_file_exists(arg);
	}
	if (mc_streq(op, "-f")) {
		return test_file_kind(arg, MC_S_IFREG);
	}
	if (mc_streq(op, "-d")) {
		return test_file_kind(arg, MC_S_IFDIR);
	}
	if (mc_streq(op, "-r")) {
		return test_access(arg, MC_R_OK);
	}
	if (mc_streq(op, "-w")) {
		return test_access(arg, MC_W_OK);
	}
	if (mc_streq(op, "-x")) {
		return test_access(arg, MC_X_OK);
	}
	if (mc_streq(op, "-z")) {
		return mc_strlen(arg) == 0;
	}
	if (mc_streq(op, "-n")) {
		return mc_strlen(arg) != 0;
	}
	return -1;
}

static int eval_binary(const char *a, const char *op, const char *b, const char *argv0, int bracket_mode) {
	(void)argv0;
	(void)bracket_mode;
	if (mc_streq(op, "=")) {
		return mc_streq(a, b);
	}
	if (mc_streq(op, "!=")) {
		return !mc_streq(a, b);
	}

	// Integer comparisons
	if (mc_streq(op, "-eq") || mc_streq(op, "-ne") || mc_streq(op, "-lt") || mc_streq(op, "-le") || mc_streq(op, "-gt") || mc_streq(op, "-ge")) {
		mc_i64 ia = 0;
		mc_i64 ib = 0;
		if (mc_parse_i64_dec(a, &ia) != 0 || mc_parse_i64_dec(b, &ib) != 0) {
			return -2; // invalid integer
		}
		if (mc_streq(op, "-eq")) return ia == ib;
		if (mc_streq(op, "-ne")) return ia != ib;
		if (mc_streq(op, "-lt")) return ia < ib;
		if (mc_streq(op, "-le")) return ia <= ib;
		if (mc_streq(op, "-gt")) return ia > ib;
		if (mc_streq(op, "-ge")) return ia >= ib;
	}
	return -1;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "test";
	int bracket_mode = mc_ends_with(argv0, "/[") || mc_streq(argv0, "[") || (mc_strlen(argv0) > 0 && argv0[mc_strlen(argv0) - 1] == '[');

	int i = 1;
	if (bracket_mode) {
		if (argc < 2) {
			mc_die_usage(argv0, "[ EXPRESSION ]");
		}
		if (!argv[argc - 1] || !mc_streq(argv[argc - 1], "]")) {
			mc_die_usage(argv0, "[ EXPRESSION ]");
		}
		argc--; // drop closing ']'
	}

	int n = argc - i;
	if (n <= 0) {
		// No expression: false (matches POSIX `test`).
		return 1;
	}

	if (n == 1) {
		const char *s = argv[i] ? argv[i] : "";
		return (mc_strlen(s) != 0) ? 0 : 1;
	}

	if (n == 2) {
		const char *op = argv[i] ? argv[i] : "";
		const char *arg = argv[i + 1] ? argv[i + 1] : "";
		int r = eval_unary(op, arg, argv0, bracket_mode);
		if (r < 0) {
			if (bracket_mode) mc_die_usage(argv0, "[ EXPRESSION ]");
			mc_die_usage(argv0, "test EXPRESSION");
		}
		return r ? 0 : 1;
	}

	if (n == 3) {
		const char *a = argv[i] ? argv[i] : "";
		const char *op = argv[i + 1] ? argv[i + 1] : "";
		const char *b = argv[i + 2] ? argv[i + 2] : "";
		int r = eval_binary(a, op, b, argv0, bracket_mode);
		if (r == -2) {
			// Invalid integer.
			if (bracket_mode) mc_die_usage(argv0, "[ EXPRESSION ]");
			mc_die_usage(argv0, "test EXPRESSION");
		}
		if (r < 0) {
			if (bracket_mode) mc_die_usage(argv0, "[ EXPRESSION ]");
			mc_die_usage(argv0, "test EXPRESSION");
		}
		return r ? 0 : 1;
	}

	if (bracket_mode) mc_die_usage(argv0, "[ EXPRESSION ]");
	mc_die_usage(argv0, "test EXPRESSION");
}
