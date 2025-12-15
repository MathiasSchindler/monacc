#include "mc.h"

static void date_write_char(const char *argv0, char c) {
	mc_i64 w = mc_write_all(1, &c, 1);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static void date_write_u64(const char *argv0, mc_u64 v) {
	mc_i64 w = mc_write_u64_dec(1, v);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static void date_write_2(const char *argv0, mc_u32 v) {
	char buf[2];
	buf[0] = (char)('0' + (char)((v / 10u) % 10u));
	buf[1] = (char)('0' + (char)(v % 10u));
	mc_i64 w = mc_write_all(1, buf, 2);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

static void date_write_4(const char *argv0, mc_u32 v) {
	char buf[4];
	buf[0] = (char)('0' + (char)((v / 1000u) % 10u));
	buf[1] = (char)('0' + (char)((v / 100u) % 10u));
	buf[2] = (char)('0' + (char)((v / 10u) % 10u));
	buf[3] = (char)('0' + (char)(v % 10u));
	mc_i64 w = mc_write_all(1, buf, 4);
	if (w < 0) mc_die_errno(argv0, "write", w);
}

// Convert days since 1970-01-01 to civil date (UTC) using a no-libc algorithm.
// Based on well-known civil-from-days transformation.
static void date_civil_from_days(mc_i64 z, mc_i32 *out_y, mc_u32 *out_m, mc_u32 *out_d) {
	// Shift to days since 0000-03-01.
	z += 719468;
	mc_i64 era = (z >= 0) ? (z / 146097) : ((z - 146096) / 146097);
	mc_i64 doe = z - era * 146097;                                    // [0, 146096]
	mc_i64 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
	mc_i64 y = yoe + era * 400;
	mc_i64 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);              // [0, 365]
	mc_i64 mp = (5 * doy + 2) / 153;                                   // [0, 11]
	mc_i64 d = doy - (153 * mp + 2) / 5 + 1;                           // [1, 31]
	mc_i64 m = mp + (mp < 10 ? 3 : -9);                                // [1, 12]
	y += (m <= 2);
	*out_y = (mc_i32)y;
	*out_m = (mc_u32)m;
	*out_d = (mc_u32)d;
}

static void date_write_format_utc(const char *argv0, const char *fmt, mc_u64 epoch_sec) {
	mc_i64 t = (mc_i64)epoch_sec;
	mc_i64 days = t / 86400;
	mc_i64 sod = t - days * 86400;
	if (sod < 0) {
		sod += 86400;
		days -= 1;
	}
	mc_u32 hour = (mc_u32)(sod / 3600);
	mc_u32 min = (mc_u32)((sod / 60) % 60);
	mc_u32 sec = (mc_u32)(sod % 60);

	mc_i32 year = 1970;
	mc_u32 month = 1;
	mc_u32 day = 1;
	date_civil_from_days(days, &year, &month, &day);

	for (mc_usize i = 0; fmt && fmt[i]; i++) {
		char c = fmt[i];
		if (c != '%') {
			date_write_char(argv0, c);
			continue;
		}
		char k = fmt[i + 1];
		if (!k) {
			date_write_char(argv0, '%');
			break;
		}
		i++;
		if (k == '%') {
			date_write_char(argv0, '%');
		} else if (k == 'Y') {
			// Clamp to 0000..9999 for fixed-width.
			mc_u32 y = (year < 0) ? 0u : (year > 9999 ? 9999u : (mc_u32)year);
			date_write_4(argv0, y);
		} else if (k == 'm') {
			date_write_2(argv0, month);
		} else if (k == 'd') {
			date_write_2(argv0, day);
		} else if (k == 'H') {
			date_write_2(argv0, hour);
		} else if (k == 'M') {
			date_write_2(argv0, min);
		} else if (k == 'S') {
			date_write_2(argv0, sec);
		} else if (k == 's') {
			date_write_u64(argv0, epoch_sec);
		} else {
			// Unknown: print verbatim.
			date_write_char(argv0, '%');
			date_write_char(argv0, k);
		}
	}
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "date";

	// Minimal:
	// - `date` -> epoch seconds
	// - `date +FORMAT` -> formatting subset (UTC)
	const char *fmt = 0;
	if (argc > 1) {
		if (argc == 2 && argv[1] && mc_streq(argv[1], "--")) {
			// Allow "--" with nothing after it.
		} else if (argc == 2 && argv[1] && argv[1][0] == '+') {
			fmt = argv[1] + 1;
		} else {
			mc_die_usage(argv0, "date [--] [+FORMAT]");
		}
	}

	struct mc_timespec ts;
	mc_i64 r = mc_sys_clock_gettime(MC_CLOCK_REALTIME, &ts);
	if (r < 0) {
		mc_die_errno(argv0, "clock_gettime", r);
	}

	mc_u64 sec = (ts.tv_sec < 0) ? 0 : (mc_u64)ts.tv_sec;
	if (fmt) {
		date_write_format_utc(argv0, fmt, sec);
	} else {
		date_write_u64(argv0, sec);
	}
	date_write_char(argv0, '\n');
	return 0;
}
