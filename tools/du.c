#include "mc.h"

static int du_print_line(const char *argv0, mc_u64 bytes, const char *path) {
	if (mc_write_u64_dec(1, bytes) < 0) return -1;
	if (mc_write_all(1, "\t", 1) < 0) return -1;
	if (mc_write_str(1, path) < 0) return -1;
	if (mc_write_all(1, "\n", 1) < 0) return -1;
	(void)argv0;
	return 0;
}

struct du_dir_iter_ctx {
	const char *argv0;
	mc_i32 dfd;
	char *subpool;
	mc_u32 *subpool_len;
	mc_u32 *sub_offs;
	mc_u32 *sub_n;
	mc_u32 sub_offs_cap;
	mc_u32 subpool_cap;
	mc_u64 *total;
	int *io_fail;
};

static int du_dir_iter_cb(void *ctxp, const char *name, mc_u8 d_type) {
	(void)d_type;
	struct du_dir_iter_ctx *ctx = (struct du_dir_iter_ctx *)ctxp;

	struct mc_stat stc;
	mc_i64 fr = mc_sys_newfstatat(ctx->dfd, name, &stc, MC_AT_SYMLINK_NOFOLLOW);
	if (fr < 0) {
		mc_print_errno(ctx->argv0, name, fr);
		*ctx->io_fail = 1;
		return 0;
	}

	mc_u32 ct = stc.st_mode & MC_S_IFMT;
	if (ct == MC_S_IFDIR) {
		// Record for later recursion.
		mc_usize nlen = mc_strlen(name);
		if (*ctx->sub_n < ctx->sub_offs_cap && *ctx->subpool_len + (mc_u32)nlen + 1u <= ctx->subpool_cap) {
			ctx->sub_offs[*ctx->sub_n] = *ctx->subpool_len;
			for (mc_usize k = 0; k < nlen; k++) ctx->subpool[*ctx->subpool_len + (mc_u32)k] = name[k];
			ctx->subpool[*ctx->subpool_len + (mc_u32)nlen] = 0;
			*ctx->subpool_len += (mc_u32)nlen + 1u;
			(*ctx->sub_n)++;
		} else {
			// Too many subdirs; treat as error.
			mc_print_errno(ctx->argv0, name, (mc_i64)-MC_EINVAL);
			*ctx->io_fail = 1;
		}
		return 0;
	}

	// Non-directory: add its size.
	*ctx->total += (mc_u64)stc.st_size;
	return 0;
}

static mc_u64 du_sum_path(const char *argv0, const char *path, int summary_only, int depth, int *io_fail) {
	if (depth > 64) {
		mc_print_errno(argv0, path, (mc_i64)-MC_ELOOP);
		*io_fail = 1;
		return 0;
	}

	// Check type without following symlinks.
	struct mc_stat st;
	mc_i64 sr = mc_sys_newfstatat(MC_AT_FDCWD, path, &st, MC_AT_SYMLINK_NOFOLLOW);
	if (sr < 0) {
		mc_print_errno(argv0, path, sr);
		*io_fail = 1;
		return 0;
	}

	mc_u32 t = st.st_mode & MC_S_IFMT;
	if (t != MC_S_IFDIR) {
		// Count non-directories by st_size (stable across filesystems).
		mc_u64 total = (mc_u64)st.st_size;
		if (du_print_line(argv0, total, path) != 0) {
			mc_die_errno(argv0, "write", -1);
		}
		return total;
	}

	// Directory: traverse children.
	mc_i64 dfd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY | MC_O_NOFOLLOW, 0);
	if (dfd < 0) {
		// If it's a symlink (ELOOP), count the symlink itself (already stat'ed).
		if ((mc_u64)(-dfd) == (mc_u64)MC_ELOOP) {
			mc_u64 total = (mc_u64)st.st_size;
			if (du_print_line(argv0, total, path) != 0) mc_die_errno(argv0, "write", -1);
			return total;
		}
		mc_print_errno(argv0, path, dfd);
		*io_fail = 1;
		return 0;
	}

	// Collect subdirectory names to recurse into.
	char subpool[32768];
	mc_u32 subpool_len = 0;
	mc_u32 sub_offs[256];
	mc_u32 sub_n = 0;

	mc_u64 total = 0;
	struct du_dir_iter_ctx ictx = {
		.argv0 = argv0,
		.dfd = (mc_i32)dfd,
		.subpool = subpool,
		.subpool_len = &subpool_len,
		.sub_offs = sub_offs,
		.sub_n = &sub_n,
		.sub_offs_cap = (mc_u32)(sizeof(sub_offs) / sizeof(sub_offs[0])),
		.subpool_cap = (mc_u32)sizeof(subpool),
		.total = &total,
		.io_fail = io_fail,
	};
	mc_i64 ir = mc_for_each_dirent((mc_i32)dfd, du_dir_iter_cb, &ictx);
	if (ir < 0) {
		(void)mc_sys_close((mc_i32)dfd);
		mc_die_errno(argv0, "getdents64", ir);
	}

	(void)mc_sys_close((mc_i32)dfd);

	for (mc_u32 si = 0; si < sub_n; si++) {
		const char *subname = subpool + sub_offs[si];
		char child[4096];
		mc_join_path_or_die(argv0, path, subname, child, (mc_usize)sizeof(child));
		total += du_sum_path(argv0, child, summary_only, depth + 1, io_fail);
	}

	if (!summary_only) {
		if (du_print_line(argv0, total, path) != 0) {
			mc_die_errno(argv0, "write", -1);
		}
	}

	return total;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "du";

	int summary_only = 0;
	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-s")) {
			summary_only = 1;
			continue;
		}
		mc_die_usage(argv0, "du [-s] [PATH...]");
	}

	int any_fail = 0;
	if (i >= argc) {
		int io_fail = 0;
		mc_u64 total = du_sum_path(argv0, ".", summary_only, 0, &io_fail);
		if (summary_only) {
			if (du_print_line(argv0, total, ".") != 0) mc_die_errno(argv0, "write", -1);
		}
		return io_fail ? 1 : 0;
	}

	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		int io_fail = 0;
		mc_u64 total = du_sum_path(argv0, path, summary_only, 0, &io_fail);
		if (summary_only) {
			if (du_print_line(argv0, total, path) != 0) mc_die_errno(argv0, "write", -1);
		}
		if (io_fail) any_fail = 1;
	}

	return any_fail ? 1 : 0;
}
