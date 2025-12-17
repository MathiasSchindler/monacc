#include "mc.h"
#include "mc_sha256.h"

static MC_NORETURN void sha256_usage(const char *argv0) {
	mc_die_usage(argv0, "sha256 [FILE...]\nsha256 -   # stdin");
}

static void hex_encode_32(const mc_u8 in[32], char out[65]) {
	static const char hex[] = "0123456789abcdef";
	for (mc_u32 i = 0; i < 32; i++) {
		mc_u8 b = in[i];
		out[i * 2u + 0u] = hex[(b >> 4) & 0xFu];
		out[i * 2u + 1u] = hex[b & 0xFu];
	}
	out[64] = 0;
}

static int hash_fd(const char *argv0, mc_i32 fd, mc_u8 out[32]) {
	mc_sha256_ctx ctx;
	mc_sha256_init(&ctx);

	mc_u8 buf[4096];
	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, sizeof(buf));
		if (r < 0) {
			mc_print_errno(argv0, "read", r);
			return 0;
		}
		if (r == 0) break;
		mc_sha256_update(&ctx, buf, (mc_usize)r);
	}

	mc_sha256_final(&ctx, out);
	return 1;
}

static int hash_path(const char *argv0, const char *path, mc_u8 out[32]) {
	if (mc_streq(path, "-")) {
		return hash_fd(argv0, 0, out);
	}

	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_print_errno(argv0, path, fd);
		return 0;
	}
	int ok = hash_fd(argv0, (mc_i32)fd, out);
	(void)mc_sys_close((mc_i32)fd);
	return ok;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "sha256";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-' && a[1] != 0 && !mc_streq(a, "-")) sha256_usage(argv0);
		break;
	}

	int rc = 0;
	mc_u8 digest[32];
	char hex[65];

	if (i >= argc) {
		if (!hash_path(argv0, "-", digest)) return 1;
		hex_encode_32(digest, hex);
		(void)mc_write_str(1, hex);
		(void)mc_write_all(1, "  -\n", 4);
		return 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i];
		if (!path) break;
		if (!hash_path(argv0, path, digest)) {
			rc = 1;
			continue;
		}
		hex_encode_32(digest, hex);
		(void)mc_write_str(1, hex);
		(void)mc_write_all(1, "  ", 2);
		(void)mc_write_str(1, mc_streq(path, "-") ? "-" : path);
		(void)mc_write_all(1, "\n", 1);
	}

	return rc;
}
