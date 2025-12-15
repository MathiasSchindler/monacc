#include "mc.h"

static mc_usize dirname_trim_trailing_slashes(const char *s, mc_usize n) {
	while (n > 0 && s[n - 1] == '/') {
		n--;
	}
	return n;
}

static int dirname_all_slashes(const char *s, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) {
		if (s[i] != '/') {
			return 0;
		}
	}
	return 1;
}

static void dirname_write_slice(const char *argv0, const char *s, mc_usize len) {
	mc_i64 w = mc_write_all(1, s, len);
	if (w < 0) {
		mc_die_errno(argv0, "write", w);
	}
	w = mc_write_all(1, "\n", 1);
	if (w < 0) {
		mc_die_errno(argv0, "write", w);
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "dirname";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || mc_streq(a, "-")) {
			break;
		}
		mc_die_usage(argv0, "dirname PATH");
	}

	if ((argc - i) != 1) {
		mc_die_usage(argv0, "dirname PATH");
	}

	const char *path = argv[i];
	if (!path) {
		path = "";
	}

	mc_usize n = mc_strlen(path);
	if (n == 0) {
		dirname_write_slice(argv0, ".", 1);
		return 0;
	}

	if (dirname_all_slashes(path, n)) {
		dirname_write_slice(argv0, "/", 1);
		return 0;
	}

	// Trim trailing slashes.
	n = dirname_trim_trailing_slashes(path, n);

	// Find last '/'.
	mc_usize slash = (mc_usize)-1;
	for (mc_usize j = n; j > 0; j--) {
		if (path[j - 1] == '/') {
			slash = j - 1;
			break;
		}
	}

	if (slash == (mc_usize)-1) {
		// No slash.
		dirname_write_slice(argv0, ".", 1);
		return 0;
	}

	// Strip trailing slashes from the directory part.
	mc_usize dirlen = slash;
	while (dirlen > 0 && path[dirlen - 1] == '/') {
		dirlen--;
	}

	if (dirlen == 0) {
		// Root.
		dirname_write_slice(argv0, "/", 1);
		return 0;
	}

	dirname_write_slice(argv0, path, dirlen);
	return 0;
}
