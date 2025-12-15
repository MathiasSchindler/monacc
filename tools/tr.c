#include "mc.h"

static void tr_mark_set(mc_u8 tbl[256], const char *set) {
	for (mc_u32 i = 0; set && set[i]; i++) {
		tbl[(mc_u8)set[i]] = 1;
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tr";

	int opt_delete = 0;
	int opt_squeeze = 0;

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
		// Options (may be combined): -d, -s
		if (a[1] && a[1] != '-' && a[2]) {
			for (mc_u32 j = 1; a[j]; j++) {
				if (a[j] == 'd') opt_delete = 1;
				else if (a[j] == 's') opt_squeeze = 1;
				else mc_die_usage(argv0, "tr [-d] [-s] SET1 [SET2]");
			}
			continue;
		}
		if (mc_streq(a, "-d")) {
			opt_delete = 1;
			continue;
		}
		if (mc_streq(a, "-s")) {
			opt_squeeze = 1;
			continue;
		}
		mc_die_usage(argv0, "tr [-d] [-s] SET1 [SET2]");
	}

	int npos = argc - i;
	if (opt_delete) {
		if (npos != 1) mc_die_usage(argv0, "tr [-d] [-s] SET1 [SET2]");
	} else {
		// Translation needs SET2, except for "-s SET1" which squeezes SET1 in-place.
		if (!(opt_squeeze && npos == 1) && npos != 2) {
			mc_die_usage(argv0, "tr [-d] [-s] SET1 [SET2]");
		}
	}

	const char *set1 = (i < argc) ? argv[i] : "";
	const char *set2;
	if (opt_delete) {
		set2 = "";
	} else if (opt_squeeze && npos == 1) {
		set2 = set1;
	} else {
		set2 = (i + 1 < argc) ? argv[i + 1] : "";
	}

	mc_u32 len1 = (mc_u32)mc_strlen(set1);
	mc_u32 len2 = (mc_u32)mc_strlen(set2);
	if (len1 == 0 || (!opt_delete && len2 == 0)) {
		mc_die_usage(argv0, "tr [-d] [-s] SET1 [SET2]");
	}

	mc_u8 map[256];
	for (mc_u32 k = 0; k < 256; k++) {
		map[k] = (mc_u8)k;
	}

	mc_u8 del[256];
	mc_u8 squeeze[256];
	for (mc_u32 k = 0; k < 256; k++) {
		del[k] = 0;
		squeeze[k] = 0;
	}

	if (opt_delete) {
		tr_mark_set(del, set1);
		if (opt_squeeze) {
			tr_mark_set(squeeze, set1);
		}
	} else {
		// Translate. If SET2 is shorter than SET1, repeat last char (minimal GNU-like behavior).
		char last = set2[len2 ? (len2 - 1u) : 0u];
		for (mc_u32 k = 0; k < len1; k++) {
			char r = (k < len2) ? set2[k] : last;
			map[(mc_u8)set1[k]] = (mc_u8)r;
		}
		if (opt_squeeze) {
			tr_mark_set(squeeze, set2);
		}
	}

	mc_u8 buf[32768];
	mc_u8 outbuf[32768];
	mc_u32 outn = 0;
	mc_u8 last_out = 0;
	int has_last = 0;
	for (;;) {
		mc_i64 r = mc_sys_read(0, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}
		for (mc_i64 j = 0; j < r; j++) {
			mc_u8 c = buf[j];
			if (opt_delete && del[c]) {
				continue;
			}
			mc_u8 out = opt_delete ? c : map[c];
			if (opt_squeeze && squeeze[out] && has_last && last_out == out) {
				continue;
			}
			outbuf[outn++] = out;
			last_out = out;
			has_last = 1;
			if (outn == (mc_u32)sizeof(outbuf)) {
				mc_i64 w = mc_write_all(1, outbuf, (mc_usize)outn);
				if (w < 0) mc_die_errno(argv0, "write", w);
				outn = 0;
			}
		}
		if (outn) {
			mc_i64 w = mc_write_all(1, outbuf, (mc_usize)outn);
			if (w < 0) mc_die_errno(argv0, "write", w);
			outn = 0;
		}
	}
	return 0;
}
