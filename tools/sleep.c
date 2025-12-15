#include "mc.h"

static void sleep_parse_timespec_or_die(const char *argv0, const char *s, struct mc_timespec *out) {
	if (!s || !*s || !out) {
		mc_die_usage(argv0, "sleep SECONDS");
	}

	mc_u64 sec = 0;
	mc_u32 nsec = 0;
	int saw_digit = 0;
	int saw_dot = 0;
	mc_u32 frac_digits = 0;

	for (const char *p = s; *p; p++) {
		char c = *p;
		if (c >= '0' && c <= '9') {
			saw_digit = 1;
			if (!saw_dot) {
				mc_u64 d = (mc_u64)(c - '0');
				if (sec > (~(mc_u64)0) / 10u) mc_die_usage(argv0, "sleep SECONDS");
				sec = sec * 10u + d;
			} else {
				if (frac_digits < 9u) {
					nsec = nsec * 10u + (mc_u32)(c - '0');
					frac_digits++;
				}
			}
			continue;
		}
		if (c == '.' && !saw_dot) {
			saw_dot = 1;
			continue;
		}
		// Unknown character.
		mc_die_usage(argv0, "sleep SECONDS");
	}

	if (!saw_digit) {
		mc_die_usage(argv0, "sleep SECONDS");
	}

	// Scale fractional part to nanoseconds.
	while (frac_digits < 9u) {
		nsec *= 10u;
		frac_digits++;
	}

	if (sec > 0x7FFFFFFFFFFFFFFFULL) {
		mc_die_usage(argv0, "sleep SECONDS");
	}
	out->tv_sec = (mc_i64)sec;
	out->tv_nsec = (mc_i64)nsec;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "sleep";

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
		// Minimal sleep has no flags.
		mc_die_usage(argv0, "sleep SECONDS");
	}

	if (i >= argc || (argc - i) != 1) {
		mc_die_usage(argv0, "sleep SECONDS");
	}

	struct mc_timespec req;
	struct mc_timespec rem;
	sleep_parse_timespec_or_die(argv0, argv[i], &req);
	if (req.tv_sec == 0 && req.tv_nsec == 0) return 0;

	for (;;) {
		mc_i64 r = mc_sys_nanosleep(&req, &rem);
		if (r == 0) {
			break;
		}
		if (r < 0 && (mc_u64)(-r) == (mc_u64)MC_EINTR) {
			req = rem;
			continue;
		}
		mc_die_errno(argv0, "nanosleep", r);
	}
	return 0;
}
