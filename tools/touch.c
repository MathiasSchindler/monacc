#include "mc.h"

static int touch_is_digit(char c) {
	return (c >= '0' && c <= '9');
}

static int touch_parse_2(const char *p, mc_u32 *out) {
	if (!touch_is_digit(p[0]) || !touch_is_digit(p[1])) return -1;
	*out = (mc_u32)(p[0] - '0') * 10u + (mc_u32)(p[1] - '0');
	return 0;
}

static int touch_parse_4(const char *p, mc_u32 *out) {
	if (!touch_is_digit(p[0]) || !touch_is_digit(p[1]) || !touch_is_digit(p[2]) || !touch_is_digit(p[3])) return -1;
	*out = (mc_u32)(p[0] - '0') * 1000u + (mc_u32)(p[1] - '0') * 100u + (mc_u32)(p[2] - '0') * 10u + (mc_u32)(p[3] - '0');
	return 0;
}

static int touch_is_leap_year(mc_i32 y) {
	return ((y % 4) == 0) && (((y % 100) != 0) || ((y % 400) == 0));
}

static mc_i64 touch_days_from_civil(mc_i32 y, mc_u32 m, mc_u32 d) {
	// Days since 1970-01-01 (UTC) for Gregorian calendar.
	// Based on Howard Hinnant's civil calendar algorithms.
	y -= (m <= 2u);
	mc_i32 era = (y >= 0) ? (y / 400) : ((y - 399) / 400);
	mc_u32 yoe = (mc_u32)(y - era * 400);
	mc_u32 mp = m + (m > 2u ? (mc_u32)-3 : 9u);
	mc_u32 doy = (153u * mp + 2u) / 5u + d - 1u;
	mc_u32 doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;
	return (mc_i64)era * 146097 + (mc_i64)doe - 719468;
}

static void touch_civil_from_days(mc_i64 z, mc_i32 *y, mc_u32 *m, mc_u32 *d) {
	z += 719468;
	mc_i64 era = (z >= 0) ? (z / 146097) : ((z - 146096) / 146097);
	mc_u32 doe = (mc_u32)(z - era * 146097);
	mc_u32 yoe = (doe - doe / 1460u + doe / 36524u - doe / 146096u) / 365u;
	mc_i32 yy = (mc_i32)yoe + (mc_i32)era * 400;
	mc_u32 doy = doe - (365u * yoe + yoe / 4u - yoe / 100u);
	mc_u32 mp = (5u * doy + 2u) / 153u;
	mc_u32 dd = doy - (153u * mp + 2u) / 5u + 1u;
	mc_u32 mm = mp + (mp < 10u ? 3u : (mc_u32)-9);
	yy += (mm <= 2u);
	*y = yy;
	*m = mm;
	*d = dd;
}

static int touch_days_in_month(mc_i32 y, mc_u32 m) {
	static const mc_u8 dim[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
	if (m < 1u || m > 12u) return 0;
	int v = (int)dim[m - 1u];
	if (m == 2u && touch_is_leap_year(y)) v++;
	return v;
}

static int touch_parse_stamp(const char *s, mc_i32 *out_year, mc_u32 *out_mon, mc_u32 *out_day, mc_u32 *out_hour, mc_u32 *out_min, mc_u32 *out_sec) {
	// Format: [[CC]YY]MMDDhhmm[.ss]
	// Supported forms (digits excluding optional .ss):
	//   MMDDhhmm (8)
	//   YYMMDDhhmm (10)
	//   CCYYMMDDhhmm (12)
	const char *dot = 0;
	for (mc_u32 i = 0; s[i]; i++) {
		if (s[i] == '.') {
			dot = s + i;
			break;
		}
	}

	mc_u32 len_digits = 0;
	for (mc_u32 i = 0; s[i]; i++) {
		if (s[i] == '.') break;
		if (!touch_is_digit(s[i])) return -1;
		len_digits++;
	}

	mc_u32 sec = 0;
	if (dot) {
		if (dot[1] == 0 || dot[2] == 0 || dot[3] != 0) return -1;
		if (touch_parse_2(dot + 1, &sec) != 0) return -1;
	}

	mc_i32 year = -1;
	const char *p = s;
	if (len_digits == 8u) {
		// no year
		p = s;
	} else if (len_digits == 10u) {
		mc_u32 yy = 0;
		if (touch_parse_2(s, &yy) != 0) return -1;
		// Common POSIX-ish pivot.
		year = (yy >= 69u) ? (1900 + (mc_i32)yy) : (2000 + (mc_i32)yy);
		p = s + 2;
	} else if (len_digits == 12u) {
		mc_u32 yyyy = 0;
		if (touch_parse_4(s, &yyyy) != 0) return -1;
		year = (mc_i32)yyyy;
		p = s + 4;
	} else {
		return -1;
	}

	mc_u32 mon = 0, day = 0, hour = 0, min = 0;
	if (touch_parse_2(p + 0, &mon) != 0) return -1;
	if (touch_parse_2(p + 2, &day) != 0) return -1;
	if (touch_parse_2(p + 4, &hour) != 0) return -1;
	if (touch_parse_2(p + 6, &min) != 0) return -1;

	*out_year = year;
	*out_mon = mon;
	*out_day = day;
	*out_hour = hour;
	*out_min = min;
	*out_sec = sec;
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;

	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "touch";
	const char *tstamp = 0;

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-t")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "touch [-t STAMP] [--] FILE...");
			tstamp = argv[i + 1];
			i++;
			continue;
		}
		if (a[1] == 't' && a[2] != 0) {
			// Allow -tSTAMP as a small convenience.
			tstamp = a + 2;
			continue;
		}
		mc_die_usage(argv0, "touch [-t STAMP] [--] FILE...");
	}

	if (i >= argc) {
		mc_die_usage(argv0, "touch [-t STAMP] [--] FILE...");
	}

	struct mc_timespec times[2];
	if (!tstamp) {
		struct mc_timespec now;
		mc_i64 tr = mc_sys_clock_gettime(MC_CLOCK_REALTIME, &now);
		if (tr < 0) {
			mc_die_errno(argv0, "clock_gettime", tr);
		}
		times[0] = now;
		times[1] = now;
	} else {
		mc_i32 year = -1;
		mc_u32 mon = 0, day = 0, hour = 0, min = 0, sec = 0;
		if (touch_parse_stamp(tstamp, &year, &mon, &day, &hour, &min, &sec) != 0) {
			mc_die_usage(argv0, "touch [-t [[CC]YY]MMDDhhmm[.ss]] [--] FILE...");
		}

		if (year < 0) {
			// No year given: use current year (UTC).
			struct mc_timespec now;
			mc_i64 tr = mc_sys_clock_gettime(MC_CLOCK_REALTIME, &now);
			if (tr < 0) mc_die_errno(argv0, "clock_gettime", tr);
			mc_i64 days = (mc_i64)((mc_u64)now.tv_sec / 86400u);
			mc_i32 cy;
			mc_u32 cm, cd;
			touch_civil_from_days(days, &cy, &cm, &cd);
			year = cy;
		}

		if (mon < 1u || mon > 12u) mc_die_usage(argv0, "touch [-t [[CC]YY]MMDDhhmm[.ss]] [--] FILE...");
		int dim = touch_days_in_month(year, mon);
		if (day < 1u || day > (mc_u32)dim) mc_die_usage(argv0, "touch [-t [[CC]YY]MMDDhhmm[.ss]] [--] FILE...");
		if (hour > 23u || min > 59u || sec > 59u) mc_die_usage(argv0, "touch [-t [[CC]YY]MMDDhhmm[.ss]] [--] FILE...");

		mc_i64 days = touch_days_from_civil(year, mon, day);
		mc_i64 ts = days * 86400 + (mc_i64)hour * 3600 + (mc_i64)min * 60 + (mc_i64)sec;
		times[0].tv_sec = ts;
		times[0].tv_nsec = 0;
		times[1] = times[0];
	}

	int any_fail = 0;
	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		mc_i64 fd = mc_sys_openat(
			MC_AT_FDCWD,
			path,
			MC_O_WRONLY | MC_O_CREAT | MC_O_CLOEXEC,
			0666);
		if (fd < 0) {
			mc_print_errno(argv0, path, fd);
			any_fail = 1;
			continue;
		}
		(void)mc_sys_close((mc_i32)fd);

		mc_i64 ur = mc_sys_utimensat(MC_AT_FDCWD, path, times, 0);
		if (ur < 0) {
			mc_print_errno(argv0, path, ur);
			any_fail = 1;
			continue;
		}
	}

	return any_fail ? 1 : 0;
}
