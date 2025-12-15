#include "mc.h"

static mc_i32 wc_fd(mc_i32 fd, mc_u64 *out_lines, mc_u64 *out_words, mc_u64 *out_bytes) {
	mc_u8 buf[32768];
	mc_u64 lines = 0;
	mc_u64 words = 0;
	mc_u64 bytes = 0;
	int in_word = 0;
	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			return (mc_i32)r; // negative errno
		}
		if (r == 0) {
			break;
		}
		bytes += (mc_u64)r;
		for (mc_i64 i = 0; i < r; i++) {
			mc_u8 c = buf[i];
			if (c == (mc_u8)'\n') {
				lines++;
			}
			if (mc_is_space_ascii(c)) {
				in_word = 0;
			} else {
				if (!in_word) {
					words++;
					in_word = 1;
				}
			}
		}
	}
	*out_lines = lines;
	*out_words = words;
	*out_bytes = bytes;
	return 0;
}

static int wc_path(const char *argv0, const char *path, mc_u64 *out_lines, mc_u64 *out_words, mc_u64 *out_bytes) {
	if (mc_streq(path, "-")) {
		mc_i32 r = wc_fd(0, out_lines, out_words, out_bytes);
		return (r < 0) ? 1 : 0;
	}

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_print_errno(argv0, path, fd);
		return 1;
	}

	mc_i32 rr = wc_fd((mc_i32)fd, out_lines, out_words, out_bytes);
	(void)mc_sys_close((mc_i32)fd);
	if (rr < 0) {
		mc_print_errno(argv0, path, (mc_i64)rr);
		return 1;
	}
	return 0;
}

static int wc_write_counts(const char *argv0, mc_u64 lines, mc_u64 words, mc_u64 bytes, int show_lines, int show_words, int show_bytes, const char *label, int have_label) {
	(void)argv0;
	int wrote_any = 0;
	if (show_lines) {
		if (mc_write_u64_dec(1, lines) < 0) return 1;
		wrote_any = 1;
	}
	if (show_words) {
		if (wrote_any) {
			if (mc_write_all(1, " ", 1) < 0) return 1;
		}
		if (mc_write_u64_dec(1, words) < 0) return 1;
		wrote_any = 1;
	}
	if (show_bytes) {
		if (wrote_any) {
			if (mc_write_all(1, " ", 1) < 0) return 1;
		}
		if (mc_write_u64_dec(1, bytes) < 0) return 1;
		wrote_any = 1;
	}
	if (!wrote_any) {
		if (mc_write_u64_dec(1, lines) < 0) return 1;
		if (mc_write_all(1, " ", 1) < 0) return 1;
		if (mc_write_u64_dec(1, words) < 0) return 1;
		if (mc_write_all(1, " ", 1) < 0) return 1;
		if (mc_write_u64_dec(1, bytes) < 0) return 1;
	}
	if (have_label) {
		if (mc_write_all(1, " ", 1) < 0) return 1;
		if (mc_write_all(1, label, mc_strlen(label)) < 0) return 1;
	}
	if (mc_write_all(1, "\n", 1) < 0) return 1;
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "wc";

	int show_lines = 0;
	int show_words = 0;
	int show_bytes = 0;

	int i = 1;
	for (; i < argc && argv[i]; i++) {
		const char *a = argv[i];
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] != '-' || a[1] == '\0') {
			break;
		}
		for (mc_usize j = 1; a[j] != '\0'; j++) {
			char c = a[j];
			if (c == 'l') {
				show_lines = 1;
				continue;
			}
			if (c == 'w') {
				show_words = 1;
				continue;
			}
			if (c == 'c') {
				show_bytes = 1;
				continue;
			}
			mc_die_usage(argv0, "wc [-l] [-w] [-c] [--] [FILE...]");
		}
	}

	if (!show_lines && !show_words && !show_bytes) {
		show_lines = 1;
		show_words = 1;
		show_bytes = 1;
	}

	int any_fail = 0;
	mc_u64 total_lines = 0;
	mc_u64 total_words = 0;
	mc_u64 total_bytes = 0;
	int success_count = 0;
	int operand_count = argc - i;

	if (i >= argc) {
		mc_u64 lines = 0, words = 0, bytes = 0;
		mc_i32 rr = wc_fd(0, &lines, &words, &bytes);
		if (rr < 0) {
			mc_print_errno(argv0, "stdin", (mc_i64)rr);
			return 1;
		}
		if (wc_write_counts(argv0, lines, words, bytes, show_lines, show_words, show_bytes, "", 0) != 0) {
			return 1;
		}
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		mc_u64 lines = 0, words = 0, bytes = 0;
		int failed = wc_path(argv0, path, &lines, &words, &bytes);
		if (failed) {
			any_fail = 1;
			continue;
		}
		total_lines += lines;
		total_words += words;
		total_bytes += bytes;
		success_count++;
		if (wc_write_counts(argv0, lines, words, bytes, show_lines, show_words, show_bytes, path, 1) != 0) {
			return 1;
		}
	}

	if (operand_count > 1 && success_count > 0) {
		if (wc_write_counts(argv0, total_lines, total_words, total_bytes, show_lines, show_words, show_bytes, "total", 1) != 0) {
			return 1;
		}
	}

	return any_fail ? 1 : 0;
}
