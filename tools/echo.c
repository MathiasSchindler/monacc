#include "mc.h"

static mc_i64 echo_write_escaped(mc_i32 fd, const char *s) {
	// Interpret a tiny subset of backslash escapes.
	// Supported: \\n, \\t, \\r, \\b, \\a, \\\\, and \\0.
	for (const char *p = s; *p; p++) {
		char c = *p;
		if (c != '\\') {
			mc_i64 r = mc_write_all(fd, &c, 1);
			if (r < 0) return r;
			continue;
		}
		p++;
		if (!*p) {
			char b = '\\';
			return mc_write_all(fd, &b, 1);
		}
		char esc = *p;
		char out;
		if (esc == 'n') out = '\n';
		else if (esc == 't') out = '\t';
		else if (esc == 'r') out = '\r';
		else if (esc == 'b') out = '\b';
		else if (esc == 'a') out = '\a';
		else if (esc == '\\') out = '\\';
		else if (esc == '0') out = 0;
		else {
			// Unknown: print literally (backslash + char).
			char b = '\\';
			mc_i64 r = mc_write_all(fd, &b, 1);
			if (r < 0) return r;
			out = esc;
		}
		mc_i64 r = mc_write_all(fd, &out, 1);
		if (r < 0) return r;
	}
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "echo";

	int newline = 1;
	int escapes = 0;
	int i = 1;
	int first = 1;

	// Parse a tiny option subset: -n, -e, -E, and --.
	for (; i < argc && argv[i]; i++) {
		const char *a = argv[i];
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (!a || a[0] != '-' || a[1] == 0) {
			break;
		}
		if (mc_streq(a, "-n")) {
			newline = 0;
			continue;
		}
		if (mc_streq(a, "-e")) {
			escapes = 1;
			continue;
		}
		if (mc_streq(a, "-E")) {
			escapes = 0;
			continue;
		}
		break;
	}

	for (; i < argc; i++) {
		if (!first) {
			mc_i64 rspace = mc_write_all(1, " ", 1);
			if (rspace < 0) {
				mc_die_errno(argv0, "write", rspace);
			}
		}
		const char *s = argv[i] ? argv[i] : "";
		mc_i64 r;
		if (escapes) {
			r = echo_write_escaped(1, s);
		} else {
			r = mc_write_all(1, s, mc_strlen(s));
		}
		if (r < 0) {
			mc_die_errno(argv0, "write", r);
		}
		first = 0;
	}

	if (newline) {
		mc_i64 rnl = mc_write_all(1, "\n", 1);
		if (rnl < 0) {
			mc_die_errno(argv0, "write", rnl);
		}
	}

	return 0;
}
