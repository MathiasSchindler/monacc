#include "mc.h"

#define COLUMN_BUF_MAX (512u * 1024u)
#define COLUMN_MAX_ROWS 2048u
#define COLUMN_MAX_COLS 32u

struct cell {
	mc_u32 off;
	mc_u16 len;
};

struct row {
	mc_u32 start; // index into cells[]
	mc_u16 n;
	mc_u8 empty;
};

static int is_ws(char c) {
	return c == ' ' || c == '\t' || c == '\r';
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "column";

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) break;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (a[0] == '-') mc_die_usage(argv0, "column [FILE...]");
		break;
	}

	// Read all input (stdin or concatenated files) into a fixed buffer.
	static char buf[COLUMN_BUF_MAX + 2];
	mc_u32 used = 0;

	int have_files = (i < argc);
	int rc = 0;

	// Local helper (no libc): read until EOF, fail if buffer cap exceeded.
	// Implemented inline to avoid shared-library complexity.
	while (1) {
		if (!have_files) {
			// Read stdin once.
			while (1) {
				if (used >= COLUMN_BUF_MAX) {
					mc_die_errno(argv0, "input too large", (mc_i64)-MC_EINVAL);
				}
				mc_usize cap = (mc_usize)(COLUMN_BUF_MAX - used);
				mc_i64 n = mc_sys_read(0, buf + used, cap);
				if (n < 0) mc_die_errno(argv0, "read", n);
				if (n == 0) break;
				used += (mc_u32)n;
			}
			break;
		}

		// Read each file.
		for (; i < argc; i++) {
			const char *path = argv[i];
			if (!path) continue;
			mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
			if (fd < 0) mc_die_errno(argv0, path, fd);
			while (1) {
				if (used >= COLUMN_BUF_MAX) {
					mc_die_errno(argv0, "input too large", (mc_i64)-MC_EINVAL);
				}
				mc_usize cap = (mc_usize)(COLUMN_BUF_MAX - used);
				mc_i64 n = mc_sys_read((mc_i32)fd, buf + used, cap);
				if (n < 0) mc_die_errno(argv0, "read", n);
				if (n == 0) break;
				used += (mc_u32)n;
			}
			(void)mc_sys_close((mc_i32)fd);
		}
		break;
	}

	buf[used] = '\n';
	buf[used + 1] = 0;
	used += 1;

	static struct cell cells[COLUMN_MAX_ROWS * COLUMN_MAX_COLS];
	static struct row rows[COLUMN_MAX_ROWS];
	mc_u32 nrows = 0;
	mc_u32 ncells = 0;

	mc_u32 colw[COLUMN_MAX_COLS];
	for (mc_u32 k = 0; k < COLUMN_MAX_COLS; k++) colw[k] = 0;

	// Parse into rows and cells (whitespace-delimited).
	mc_u32 pos = 0;
	while (pos < used) {
		if (nrows >= COLUMN_MAX_ROWS) mc_die_errno(argv0, "too many lines", (mc_i64)-MC_EINVAL);

		struct row *r = &rows[nrows];
		r->start = ncells;
		r->n = 0;
		r->empty = 0;

		// Handle empty line
		if (buf[pos] == '\n') {
			r->empty = 1;
			nrows++;
			pos++;
			continue;
		}

		while (pos < used && buf[pos] != '\n') {
			while (pos < used && is_ws(buf[pos])) buf[pos++] = 0;
			if (pos >= used || buf[pos] == '\n') break;
			if (r->n >= COLUMN_MAX_COLS) mc_die_errno(argv0, "too many columns", (mc_i64)-MC_EINVAL);
			if (ncells >= (COLUMN_MAX_ROWS * COLUMN_MAX_COLS)) mc_die_errno(argv0, "too many cells", (mc_i64)-MC_EINVAL);
			mc_u32 start = pos;
			mc_u32 len = 0;
			while (pos < used && buf[pos] != '\n' && !is_ws(buf[pos])) {
				pos++;
				len++;
			}
			// terminate token
			if (pos < used && buf[pos] != '\n') buf[pos] = 0;

			cells[ncells] = (struct cell){ .off = start, .len = (mc_u16)len };
			if (len > colw[r->n]) colw[r->n] = len;
			ncells++;
			r->n++;
			if (pos < used && buf[pos] == 0) pos++; // advance past NUL
		}

		// consume newline
		while (pos < used && buf[pos] != '\n') pos++;
		if (pos < used && buf[pos] == '\n') {
			buf[pos++] = 0;
		}
		nrows++;
	}

	// Emit aligned table.
	for (mc_u32 ri = 0; ri < nrows; ri++) {
		struct row *r = &rows[ri];
		if (r->empty) {
			(void)mc_write_all(1, "\n", 1);
			continue;
		}
		for (mc_u32 ci = 0; ci < r->n; ci++) {
			struct cell *c = &cells[r->start + ci];
			(void)mc_write_all(1, buf + c->off, c->len);
			// pad (not after last column)
			if (ci + 1 < r->n) {
				mc_u32 w = colw[ci];
				mc_u32 pad = (w > c->len) ? (w - c->len) : 0;
				// at least one space
				(void)mc_write_all(1, " ", 1);
				for (mc_u32 k = 0; k < pad; k++) {
					(void)mc_write_all(1, " ", 1);
				}
			}
		}
		(void)mc_write_all(1, "\n", 1);
	}

	return rc;
}
