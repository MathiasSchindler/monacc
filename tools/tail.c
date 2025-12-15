#include "mc.h"

// Tail (streaming): keep last N lines using a fixed-size ring buffer.
// Limitations: if total buffered bytes exceed capacity, the oldest data is dropped.

#define TAIL_BUF_SIZE (1024u * 1024u) // 1 MiB
#define TAIL_MAX_LINES 8192u

struct tail_state {
	mc_u8 buf[TAIL_BUF_SIZE];
	mc_u32 head; // next write position
	mc_u32 len;  // valid bytes in buffer (<= TAIL_BUF_SIZE)

	mc_u32 starts[TAIL_MAX_LINES]; // indices in buf[] of line starts
	mc_u32 start_count;
};

static mc_u64 tail_parse_n_or_die(const char *argv0, const char *s) {
	mc_u64 n = 0;
	if (mc_parse_u64_dec(s, &n) != 0) {
		mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
	}
	return n;
}

static mc_u64 tail_parse_c_or_die(const char *argv0, const char *s) {
	return tail_parse_n_or_die(argv0, s);
}

static void tail_follow_fd(const char *argv0, mc_i32 fd) {
	mc_u8 buf[32768];
	struct mc_timespec ts;
	ts.tv_sec = 0;
	ts.tv_nsec = 200 * 1000 * 1000; // 200ms

	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			if ((mc_u64)(-r) == (mc_u64)MC_EINTR) continue;
			mc_die_errno(argv0, "read", r);
		}
		if (r > 0) {
			mc_i64 w = mc_write_all(1, buf, (mc_usize)r);
			if (w < 0) mc_die_errno(argv0, "write", w);
			continue;
		}

		// EOF: sleep briefly, then check for truncation.
		(void)mc_sys_nanosleep(&ts, 0);
		struct mc_stat st;
		mc_i64 fr = mc_sys_fstat(fd, &st);
		if (fr < 0) mc_die_errno(argv0, "fstat", fr);
		mc_i64 cur = mc_sys_lseek(fd, 0, MC_SEEK_CUR);
		if (cur < 0) mc_die_errno(argv0, "lseek", cur);
		if (st.st_size < cur) {
			mc_i64 sr = mc_sys_lseek(fd, 0, MC_SEEK_SET);
			if (sr < 0) mc_die_errno(argv0, "lseek", sr);
		}
	}
}

struct tail_bytes_state {
	mc_u8 buf[TAIL_BUF_SIZE];
	mc_u32 cap;
	mc_u32 head;
	mc_u32 len;
};

static void tail_bytes_feed(struct tail_bytes_state *st, const mc_u8 *p, mc_usize n) {
	if (st->cap == 0) return;
	for (mc_usize i = 0; i < n; i++) {
		st->buf[st->head] = p[i];
		st->head = (st->head + 1) % st->cap;
		if (st->len < st->cap) st->len++;
	}
}

static void tail_bytes_write(const char *argv0, const struct tail_bytes_state *st) {
	if (st->len == 0 || st->cap == 0) return;
	mc_u32 oldest = (st->head + st->cap - st->len) % st->cap;
	if (oldest < st->head) {
		mc_i64 w = mc_write_all(1, st->buf + oldest, (mc_usize)(st->head - oldest));
		if (w < 0) mc_die_errno(argv0, "write", w);
		return;
	}
	// Wrapped.
	mc_i64 w1 = mc_write_all(1, st->buf + oldest, (mc_usize)(st->cap - oldest));
	if (w1 < 0) mc_die_errno(argv0, "write", w1);
	mc_i64 w2 = mc_write_all(1, st->buf, (mc_usize)st->head);
	if (w2 < 0) mc_die_errno(argv0, "write", w2);
}

static void tail_drop_oldest_bytes(struct tail_state *st, mc_u32 drop) {
	if (drop >= st->len) {
		st->len = 0;
		st->start_count = 0;
		return;
	}

	// When dropping bytes, any recorded line starts that fall into the dropped region must be removed.
	mc_u32 old_len = st->len;
	st->len = old_len - drop;

	// Compute new oldest byte index.
	mc_u32 new_oldest = (st->head + (mc_u32)TAIL_BUF_SIZE - st->len) % (mc_u32)TAIL_BUF_SIZE;

	// Filter starts[] in-place to only keep those within the new buffer window.
	mc_u32 out = 0;
	for (mc_u32 i = 0; i < st->start_count; i++) {
		mc_u32 idx = st->starts[i];
		// Determine if idx is within [new_oldest, head) circular range of length st->len.
		// Convert idx to offset from new_oldest.
		mc_u32 off = (idx + (mc_u32)TAIL_BUF_SIZE - new_oldest) % (mc_u32)TAIL_BUF_SIZE;
		if (off < st->len) {
			st->starts[out++] = idx;
		}
	}
	st->start_count = out;

	// Ensure we have at least one start recorded when buffer is non-empty.
	if (st->len != 0 && st->start_count == 0) {
		st->starts[0] = new_oldest;
		st->start_count = 1;
	}
}

static void tail_record_line_start(struct tail_state *st, mc_u32 idx) {
	if (st->start_count < (mc_u32)TAIL_MAX_LINES) {
		st->starts[st->start_count++] = idx;
		return;
	}
	// If the starts ring is full, drop the oldest start.
	for (mc_u32 i = 1; i < st->start_count; i++) {
		st->starts[i - 1] = st->starts[i];
	}
	st->starts[st->start_count - 1] = idx;
}

static void tail_feed_byte(struct tail_state *st, mc_u8 b) {
	// If buffer is full, drop one byte (and any starts it invalidates).
	if (st->len == (mc_u32)TAIL_BUF_SIZE) {
		tail_drop_oldest_bytes(st, 1);
	}

	st->buf[st->head] = b;
	st->head = (st->head + 1) % (mc_u32)TAIL_BUF_SIZE;
	st->len++;

	if (b == (mc_u8)'\n') {
		// Start of next line is current head.
		tail_record_line_start(st, st->head);
	}
}

static void tail_feed(struct tail_state *st, const mc_u8 *p, mc_usize n) {
	for (mc_usize i = 0; i < n; i++) {
		tail_feed_byte(st, p[i]);
	}
}

static void tail_write_range(const char *argv0, const struct tail_state *st, mc_u32 from, mc_u32 to_exclusive) {
	if (from == to_exclusive) {
		return;
	}
	if (from < to_exclusive) {
		mc_i64 w = mc_write_all(1, st->buf + from, (mc_usize)(to_exclusive - from));
		if (w < 0) mc_die_errno(argv0, "write", w);
		return;
	}
	// Wrapped.
	mc_i64 w1 = mc_write_all(1, st->buf + from, (mc_usize)((mc_u32)TAIL_BUF_SIZE - from));
	if (w1 < 0) mc_die_errno(argv0, "write", w1);
	mc_i64 w2 = mc_write_all(1, st->buf, (mc_usize)to_exclusive);
	if (w2 < 0) mc_die_errno(argv0, "write", w2);
}

static int tail_fd(const char *argv0, mc_i32 fd, mc_u64 nlines) {
	struct tail_state st;
	st.head = 0;
	st.len = 0;
	st.start_count = 0;

	// Record the start of the first line.
	tail_record_line_start(&st, 0);

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) {
			mc_die_errno(argv0, "read", r);
		}
		if (r == 0) {
			break;
		}
		tail_feed(&st, buf, (mc_usize)r);
	}

	if (nlines == 0) {
		return 0;
	}

	// Determine which recorded start corresponds to the last N lines.
	// starts[] contains the start of each line (including a start after each newline).
	mc_u32 total_starts = st.start_count;
	if (total_starts == 0 || st.len == 0) {
		return 0;
	}

	// If the input ends with a newline, the final recorded start is for an empty line;
	// ignore it for line counting so `tail -n 2` prints the last 2 non-empty lines.
	mc_u32 effective_starts = total_starts;
	{
		mc_u32 last_idx = (st.head + (mc_u32)TAIL_BUF_SIZE - 1) % (mc_u32)TAIL_BUF_SIZE;
		if (st.buf[last_idx] == (mc_u8)'\n' && effective_starts > 0) {
			effective_starts--;
		}
	}

	// For tail semantics, printing from (effective_starts - nlines) (clamped) is acceptable.
	mc_u32 want = (nlines > (mc_u64)0xFFFFFFFFu) ? 0xFFFFFFFFu : (mc_u32)nlines;
	mc_u32 start_idx = 0;
	if (effective_starts > want) {
		start_idx = effective_starts - want;
	}

	mc_u32 from = st.starts[start_idx];
	mc_u32 to = st.head;
	// If buffer is full and head == from, that could mean "all bytes"; still write full buffer.
	if (st.len == (mc_u32)TAIL_BUF_SIZE && from == to) {
		tail_write_range(argv0, &st, to, to); // no-op
		// Write full buffer from oldest.
		mc_u32 oldest = (st.head + (mc_u32)TAIL_BUF_SIZE - st.len) % (mc_u32)TAIL_BUF_SIZE;
		tail_write_range(argv0, &st, oldest, st.head);
		return 0;
	}

	tail_write_range(argv0, &st, from, to);
	return 0;
}

// Seek-based tail -n for regular files: scan backwards for N newlines, then stream forward.
// Returns 0 on success, 1 if the fd is not seekable (ESPIPE).
static int tail_fd_lines_seek(const char *argv0, mc_i32 fd, mc_u64 nlines) {
	if (nlines == 0) return 0;

	mc_i64 end = mc_sys_lseek(fd, 0, MC_SEEK_END);
	if (end < 0) {
		if ((mc_u64)(-end) == (mc_u64)MC_ESPIPE) return 1;
		mc_die_errno(argv0, "lseek", end);
	}
	if (end == 0) return 0;

	int ignore_trailing_nl = 0;
	{
		mc_u8 last = 0;
		mc_i64 sr = mc_sys_lseek(fd, end - 1, MC_SEEK_SET);
		if (sr < 0) mc_die_errno(argv0, "lseek", sr);
		mc_i64 rr = mc_sys_read(fd, &last, 1);
		if (rr < 0) mc_die_errno(argv0, "read", rr);
		if (rr == 1 && last == (mc_u8)'\n') ignore_trailing_nl = 1;
	}

	mc_u8 buf[32768];
	mc_i64 pos = end;
	mc_u64 found = 0;
	mc_i64 start = 0;

	while (pos > 0 && found < nlines) {
		mc_i64 step = (pos > (mc_i64)sizeof(buf)) ? (mc_i64)sizeof(buf) : pos;
		pos -= step;

		mc_i64 sr = mc_sys_lseek(fd, pos, MC_SEEK_SET);
		if (sr < 0) mc_die_errno(argv0, "lseek", sr);

		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)step);
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) break;

		for (mc_i64 i = r - 1; i >= 0; i--) {
			mc_i64 abs = pos + i;
			if (ignore_trailing_nl && abs == end - 1) {
				continue;
			}
			if (buf[(mc_usize)i] == (mc_u8)'\n') {
				found++;
				if (found == nlines) {
					start = abs + 1;
					pos = 0;
					break;
				}
			}
		}
	}

	if (found < nlines) {
		start = 0;
	}

	// Stream from start to end.
	{
		mc_i64 sr = mc_sys_lseek(fd, start, MC_SEEK_SET);
		if (sr < 0) mc_die_errno(argv0, "lseek", sr);

		for (;;) {
			mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
			if (r < 0) mc_die_errno(argv0, "read", r);
			if (r == 0) break;
			mc_i64 w = mc_write_all(1, buf, (mc_usize)r);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
	}

	return 0;
}

static int tail_fd_bytes(const char *argv0, mc_i32 fd, mc_u64 nbytes) {
	if (nbytes == 0) return 0;

	// Try seek-based implementation.
	mc_i64 end = mc_sys_lseek(fd, 0, MC_SEEK_END);
	if (end >= 0) {
		mc_i64 start = 0;
		if ((mc_u64)end > nbytes) {
			// end - nbytes fits in signed range here.
			start = end - (mc_i64)nbytes;
		}
		mc_i64 sr = mc_sys_lseek(fd, start, MC_SEEK_SET);
		if (sr < 0) mc_die_errno(argv0, "lseek", sr);

		mc_u8 buf[32768];
		for (;;) {
			mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
			if (r < 0) mc_die_errno(argv0, "read", r);
			if (r == 0) break;
			mc_i64 w = mc_write_all(1, buf, (mc_usize)r);
			if (w < 0) mc_die_errno(argv0, "write", w);
		}
		return 0;
	}

	// Non-seekable fallback.
	if ((mc_u64)(-end) != (mc_u64)MC_ESPIPE) {
		mc_die_errno(argv0, "lseek", end);
	}

	struct tail_bytes_state st;
	st.cap = (nbytes > (mc_u64)TAIL_BUF_SIZE) ? (mc_u32)TAIL_BUF_SIZE : (mc_u32)nbytes;
	st.head = 0;
	st.len = 0;

	mc_u8 buf[32768];
	for (;;) {
		mc_i64 r = mc_sys_read(fd, buf, (mc_usize)sizeof(buf));
		if (r < 0) mc_die_errno(argv0, "read", r);
		if (r == 0) break;
		tail_bytes_feed(&st, buf, (mc_usize)r);
	}
	if (st.cap == 0) return 0;
	tail_bytes_write(argv0, &st);
	return 0;
}

static int tail_path(const char *argv0, const char *path, int bytes_mode, int follow, mc_u64 n) {
	if (mc_streq(path, "-")) {
		// Minimal policy: follow mode requires a seekable file.
		if (follow) mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
		if (bytes_mode) return tail_fd_bytes(argv0, 0, n);
		return tail_fd(argv0, 0, n);
	}
	
	mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, path, MC_O_RDONLY | MC_O_CLOEXEC, 0);
	if (fd < 0) {
		mc_die_errno(argv0, path, fd);
	}
	if (bytes_mode) {
		(void)tail_fd_bytes(argv0, (mc_i32)fd, n);
	} else {
		int seek_rc = tail_fd_lines_seek(argv0, (mc_i32)fd, n);
		if (seek_rc == 1) {
			if (follow) {
				(void)mc_sys_close((mc_i32)fd);
				mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
			}
			(void)tail_fd(argv0, (mc_i32)fd, n);
		}
	}
	if (follow) {
		// Ensure we start following from EOF (especially important for N==0).
		mc_i64 sr = mc_sys_lseek((mc_i32)fd, 0, MC_SEEK_END);
		if (sr < 0) mc_die_errno(argv0, "lseek", sr);
		tail_follow_fd(argv0, (mc_i32)fd);
	}
	(void)mc_sys_close((mc_i32)fd);
	return 0;
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "tail";

	int bytes_mode = 0;
	int follow = 0;
	mc_u64 n = 10;

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
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc) {
				mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
			}
			bytes_mode = 0;
			n = tail_parse_n_or_die(argv0, argv[i + 1]);
			i++;
			continue;
		}
		if (mc_streq(a, "-c")) {
			if (i + 1 >= argc) {
				mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
			}
			bytes_mode = 1;
			n = tail_parse_c_or_die(argv0, argv[i + 1]);
			i++;
			continue;
		}
		if (mc_streq(a, "-f")) {
			follow = 1;
			continue;
		}
		if (a[1] == 'n' && a[2] != 0) {
			bytes_mode = 0;
			n = tail_parse_n_or_die(argv0, a + 2);
			continue;
		}
		if (a[1] == 'c' && a[2] != 0) {
			bytes_mode = 1;
			n = tail_parse_c_or_die(argv0, a + 2);
			continue;
		}
		mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
	}

	if (i >= argc) {
		if (follow) mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
		if (bytes_mode) return tail_fd_bytes(argv0, 0, n);
		return tail_fd(argv0, 0, n);
	}

	if (follow && (i + 1 < argc)) {
		// Minimal policy: follow mode only supports a single file operand.
		mc_die_usage(argv0, "tail [-n N] [-c N] [-f] [FILE...]");
	}

	for (; i < argc; i++) {
		const char *path = argv[i] ? argv[i] : "";
		(void)tail_path(argv0, path, bytes_mode, follow, n);
	}
	return 0;
}
