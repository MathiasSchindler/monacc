#include "mc.h"

struct pt_proc {
	mc_u32 pid;
	mc_u32 ppid;
	mc_u8 state;
	char comm[32];
	mc_u32 comm_len;
};

static int pt_is_all_digits(const char *s) {
	if (!s || !*s) return 0;
	for (const char *p = s; *p; p++) {
		if (*p < '0' || *p > '9') return 0;
	}
	return 1;
}

static mc_usize pt_strnlen0(const char *s, mc_usize max) {
	mc_usize n = 0;
	while (n < max && s && s[n]) n++;
	return n;
}

static int pt_parse_u32_dec_span(const mc_u8 *p, mc_u32 n, mc_u32 *out) {
	if (!p || n == 0) return -1;
	mc_u32 i = 0;
	while (i < n && (p[i] == ' ' || p[i] == '\t' || p[i] == '\n')) i++;
	if (i >= n) return -1;
	if (p[i] < '0' || p[i] > '9') return -1;
	mc_u64 v = 0;
	while (i < n && p[i] >= '0' && p[i] <= '9') {
		v = v * 10u + (mc_u64)(p[i] - '0');
		if (v > 0xFFFFFFFFu) return -1;
		i++;
	}
	*out = (mc_u32)v;
	return 0;
}

static void pt_write_indent(mc_u32 depth) {
	for (mc_u32 i = 0; i < depth; i++) {
		(void)mc_write_all(1, "  ", 2);
	}
}

static void pt_print_line(const struct pt_proc *p, mc_u32 depth) {
	pt_write_indent(depth);
	mc_write_u64_dec(1, (mc_u64)p->pid);
	(void)mc_write_all(1, " ", 1);
	mc_write_u64_dec(1, (mc_u64)p->ppid);
	(void)mc_write_all(1, " ", 1);
	(void)mc_write_all(1, &p->state, 1);
	(void)mc_write_all(1, " ", 1);
	if (p->comm_len) (void)mc_write_all(1, p->comm, p->comm_len);
	(void)mc_write_all(1, "\n", 1);
}

static int pt_pid_index(struct pt_proc *procs, mc_u32 n, mc_u32 pid) {
	for (mc_u32 i = 0; i < n; i++) {
		if (procs[i].pid == pid) return (int)i;
	}
	return -1;
}

static void pt_sort_u32(mc_u32 *a, mc_u32 n) {
	for (mc_u32 i = 1; i < n; i++) {
		mc_u32 v = a[i];
		mc_u32 j = i;
		while (j > 0 && a[j - 1] > v) {
			a[j] = a[j - 1];
			j--;
		}
		a[j] = v;
	}
}

static void pt_collect_children(struct pt_proc *procs, mc_u32 n, mc_u32 parent_pid, mc_u32 *out_idx, mc_u32 *out_cnt, mc_u32 cap) {
	mc_u32 cnt = 0;
	for (mc_u32 i = 0; i < n; i++) {
		if (procs[i].ppid == parent_pid && procs[i].pid != parent_pid) {
			if (cnt < cap) out_idx[cnt] = i;
			cnt++;
		}
	}
	// sort by pid (stable enough)
	if (cnt > cap) cnt = cap;
	for (mc_u32 i = 1; i < cnt; i++) {
		mc_u32 v = out_idx[i];
		mc_u32 j = i;
		while (j > 0 && procs[out_idx[j - 1]].pid > procs[v].pid) {
			out_idx[j] = out_idx[j - 1];
			j--;
		}
		out_idx[j] = v;
	}
	*out_cnt = cnt;
}

static void pt_print_tree(struct pt_proc *procs, mc_u32 n, mc_u32 root_idx) {
	// Small explicit stack to avoid deep recursion.
	// Each frame: proc index + next child offset + depth.
	struct frame {
		mc_u32 idx;
		mc_u32 next_child;
		mc_u32 depth;
	} stack[256];
	mc_u32 sp = 0;

	pt_print_line(&procs[root_idx], 0);
	stack[sp++] = (struct frame){.idx = root_idx, .next_child = 0, .depth = 0};

	while (sp) {
		struct frame *f = &stack[sp - 1];
		mc_u32 child_idx_buf[256];
		mc_u32 child_cnt = 0;
		pt_collect_children(procs, n, procs[f->idx].pid, child_idx_buf, &child_cnt, (mc_u32)(sizeof(child_idx_buf) / sizeof(child_idx_buf[0])));

		if (f->next_child >= child_cnt) {
			sp--;
			continue;
		}

		mc_u32 cidx = child_idx_buf[f->next_child++];
		mc_u32 depth = f->depth + 1;
		pt_print_line(&procs[cidx], depth);
		if (sp < (mc_u32)(sizeof(stack) / sizeof(stack[0])) && depth < 64) {
			stack[sp++] = (struct frame){.idx = cidx, .next_child = 0, .depth = depth};
		}
	}
}

static int pt_parse_stat_into(struct pt_proc *out, const mc_u8 *buf, mc_u32 len) {
	// Extract comm: second field in /proc/PID/stat, in parentheses. Use first '(' and last ')'.
	mc_u32 lp = 0xFFFFFFFFu;
	mc_u32 rp = 0xFFFFFFFFu;
	for (mc_u32 i = 0; i < len; i++) {
		if (buf[i] == '(') {
			lp = i;
			break;
		}
	}
	for (mc_u32 i = len; i > 0; i--) {
		if (buf[i - 1] == ')') {
			rp = i - 1;
			break;
		}
	}
	if (lp == 0xFFFFFFFFu || rp == 0xFFFFFFFFu || rp <= lp + 1) return -1;

	// state + ppid: after ") ", then "<state> <ppid>"
	if (rp + 3u >= len) return -1;
	if (buf[rp + 1] != ' ') return -1;
	out->state = buf[rp + 2];
	if (pt_parse_u32_dec_span(buf + rp + 3u, len - (rp + 3u), &out->ppid) != 0) return -1;

	// comm
	mc_u32 cn = rp - (lp + 1);
	if (cn > (mc_u32)sizeof(out->comm)) cn = (mc_u32)sizeof(out->comm);
	for (mc_u32 i = 0; i < cn; i++) out->comm[i] = (char)buf[lp + 1 + i];
	out->comm_len = cn;
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "pstree";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a || a[0] != '-' || mc_streq(a, "-")) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		mc_die_usage(argv0, "pstree");
	}
	if (i != argc) mc_die_usage(argv0, "pstree");

	mc_i64 procfd = mc_sys_openat(MC_AT_FDCWD, "/proc", MC_O_RDONLY | MC_O_CLOEXEC | MC_O_DIRECTORY, 0);
	if (procfd < 0) mc_die_errno(argv0, "/proc", procfd);

	// Cap to keep the tool small and predictable.
	struct pt_proc procs[4096];
	mc_u32 nprocs = 0;

	mc_u8 d_buf[32768];
	for (;;) {
		mc_i64 nread = mc_sys_getdents64((mc_i32)procfd, d_buf, (mc_u32)sizeof(d_buf));
		if (nread < 0) mc_die_errno(argv0, "getdents64", nread);
		if (nread == 0) break;

		mc_u32 bpos = 0;
		while (bpos < (mc_u32)nread) {
			struct mc_dirent64 *d = (struct mc_dirent64 *)(d_buf + bpos);
			const char *name = d->d_name;
			if (pt_is_all_digits(name) && nprocs < (mc_u32)(sizeof(procs) / sizeof(procs[0]))) {
				// Build "PID/stat" relative path
				char rel[64];
				mc_usize pn = pt_strnlen0(name, 32);
				if (pn && pn + 5 + 1 <= sizeof(rel)) {
					for (mc_usize k = 0; k < pn; k++) rel[k] = name[k];
					rel[pn + 0] = '/';
					rel[pn + 1] = 's';
					rel[pn + 2] = 't';
					rel[pn + 3] = 'a';
					rel[pn + 4] = 't';
					rel[pn + 5] = 0;

					mc_i64 fd = mc_sys_openat((mc_i32)procfd, rel, MC_O_RDONLY | MC_O_CLOEXEC, 0);
					if (fd >= 0) {
						mc_u8 buf[1024];
						mc_i64 nn = mc_sys_read((mc_i32)fd, buf, sizeof(buf) - 1);
						(void)mc_sys_close((mc_i32)fd);
						if (nn > 0) {
							buf[(mc_u32)nn] = 0;
							struct pt_proc p;
							mc_memset(&p, 0, sizeof(p));
							if (mc_parse_u32_dec(name, &p.pid) == 0 && pt_parse_stat_into(&p, buf, (mc_u32)nn) == 0) {
								procs[nprocs++] = p;
							}
						}
					}
				}
			}
			bpos += d->d_reclen;
		}
	}

	(void)mc_sys_close((mc_i32)procfd);

	(void)mc_write_all(1, "PID PPID S CMD\n", 15);

	// Roots: ppid not found (or 0) or self-parented.
	mc_u32 roots[4096];
	mc_u32 nroots = 0;
	for (mc_u32 idx = 0; idx < nprocs; idx++) {
		mc_u32 ppid = procs[idx].ppid;
		if (ppid == 0 || ppid == procs[idx].pid || pt_pid_index(procs, nprocs, ppid) < 0) {
			roots[nroots++] = idx;
		}
	}

	// Sort roots by pid for stable output.
	for (mc_u32 i2 = 1; i2 < nroots; i2++) {
		mc_u32 v = roots[i2];
		mc_u32 j = i2;
		while (j > 0 && procs[roots[j - 1]].pid > procs[v].pid) {
			roots[j] = roots[j - 1];
			j--;
		}
		roots[j] = v;
	}

	for (mc_u32 r = 0; r < nroots; r++) {
		pt_print_tree(procs, nprocs, roots[r]);
	}

	return 0;
}
