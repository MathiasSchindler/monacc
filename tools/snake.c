#include "mc.h"
#include "mc_net.h"

// Minimal ANSI-terminal snake game.
// Controls: arrows or WASD. Quit: q.

#define MC_TCGETS 0x5401u
#define MC_TCSETS 0x5402u
#define MC_TIOCGWINSZ 0x5413u

#define MC_IGNBRK 0000001u
#define MC_BRKINT 0000002u
#define MC_IGNPAR 0000004u
#define MC_PARMRK 0000010u
#define MC_INPCK 0000020u
#define MC_ISTRIP 0000040u
#define MC_INLCR 0000100u
#define MC_IGNCR 0000200u
#define MC_ICRNL 0000400u
#define MC_IUCLC 0001000u
#define MC_IXON 0002000u
#define MC_IXANY 0004000u
#define MC_IXOFF 0010000u

#define MC_OPOST 0000001u

#define MC_CSIZE 0000060u
#define MC_CS8 0000060u
#define MC_PARENB 0000400u

#define MC_ISIG 0000001u
#define MC_ICANON 0000002u
#define MC_ECHO 0000010u
#define MC_ECHONL 0000100u
#define MC_IEXTEN 0100000u

#define MC_VTIME 5
#define MC_VMIN 6

struct mc_termios {
	mc_u32 c_iflag;
	mc_u32 c_oflag;
	mc_u32 c_cflag;
	mc_u32 c_lflag;
	mc_u8 c_line;
	mc_u8 c_cc[32];
	mc_u32 c_ispeed;
	mc_u32 c_ospeed;
};

struct mc_winsize {
	mc_u16 ws_row;
	mc_u16 ws_col;
	mc_u16 ws_xpixel;
	mc_u16 ws_ypixel;
};

static int g_have_termios = 0;
static struct mc_termios g_old_termios;

static void write_all_or_die(const char *argv0, const void *buf, mc_usize n) {
	mc_i64 r = mc_write_all(1, buf, n);
	if (r < 0) mc_die_errno(argv0, "write", r);
}

static void write_str_or_die(const char *argv0, const char *s) {
	write_all_or_die(argv0, s, mc_strlen(s));
}

static void restore_terminal_best_effort(void) {
	if (!g_have_termios) return;
	(void)mc_sys_ioctl(0, MC_TCSETS, &g_old_termios);
	g_have_termios = 0;
}

static int enable_raw_terminal(const char *argv0) {
	struct mc_termios tio;
	mc_i64 r = mc_sys_ioctl(0, MC_TCGETS, &tio);
	if (r < 0) return 0;

	g_old_termios = tio;
	g_have_termios = 1;

	// raw-ish: no echo, no canonical, no signals, no IXON
	tio.c_iflag &= ~(MC_IGNBRK | MC_BRKINT | MC_PARMRK | MC_ISTRIP | MC_INLCR | MC_IGNCR | MC_ICRNL | MC_IXON);
	tio.c_oflag &= ~(MC_OPOST);
	tio.c_cflag &= ~(MC_PARENB);
	tio.c_cflag |= MC_CS8;
	tio.c_lflag &= ~(MC_ECHO | MC_ECHONL | MC_ICANON | MC_ISIG | MC_IEXTEN);
	tio.c_cc[MC_VMIN] = 0;
	tio.c_cc[MC_VTIME] = 0;

	r = mc_sys_ioctl(0, MC_TCSETS, &tio);
	if (r < 0) {
		restore_terminal_best_effort();
		mc_die_errno(argv0, "ioctl(TCSETS)", r);
	}
	return 1;
}

static void ansi_enter_game(const char *argv0) {
	(void)argv0;
	write_str_or_die(argv0, "\x1b[?25l\x1b[2J\x1b[H");
}

static void ansi_leave_game(const char *argv0) {
	(void)argv0;
	write_str_or_die(argv0, "\x1b[?25h\x1b[0m\x1b[H\x1b[2J");
}

static void query_terminal_size(mc_i32 *out_cols, mc_i32 *out_rows) {
	struct mc_winsize ws;
	mc_memset(&ws, 0, sizeof(ws));
	(void)mc_sys_ioctl(1, MC_TIOCGWINSZ, &ws);
	mc_i32 cols = ws.ws_col ? (mc_i32)ws.ws_col : 80;
	mc_i32 rows = ws.ws_row ? (mc_i32)ws.ws_row : 24;
	*out_cols = cols;
	*out_rows = rows;
}

static int compute_board_size(mc_i32 cols, mc_i32 rows, mc_i32 *out_w, mc_i32 *out_h) {
	// Layout:
	//  - 1 status line
	//  - top border
	//  - h rows
	//  - bottom border
	// => total rows needed: h + 3
	// We draw each cell as 2 characters wide to compensate for typical terminal
	// font aspect ratio (cells look closer to square).
	// Columns: '+' + (w*2) + '+' => (w*2) + 2
	if (cols < 24 || rows < 8) return 0;

	mc_i32 w = (cols - 2) / 2;
	mc_i32 h = rows - 3;
	// Keep within a small, predictable max so we can use a fixed snake buffer.
	if (w > 60) w = 60;
	if (h > 25) h = 25;
	// Minimum playable area (but never exceed terminal-derived size)
	if (w < 10) w = 10;
	if (h < 5) h = 5;
	if (w > (cols - 2) / 2) w = (cols - 2) / 2;
	if (h > rows - 3) h = rows - 3;
	if (w < 10 || h < 5) return 0;

	*out_w = w;
	*out_h = h;
	return 1;
}

static mc_u32 rng_next_u32(mc_u64 *state) {
	// xorshift64*
	mc_u64 x = *state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	x *= 2685821657736338717ull;
	return (mc_u32)(x >> 32);
}

static void rng_seed(mc_u64 *state) {
	mc_u64 s = 0;
	mc_i64 r = mc_sys_getrandom(&s, sizeof(s), 0);
	if (r != (mc_i64)sizeof(s) || s == 0) {
		struct mc_timespec ts;
		(void)mc_sys_clock_gettime(MC_CLOCK_MONOTONIC, &ts);
		s = (mc_u64)ts.tv_nsec ^ ((mc_u64)ts.tv_sec << 32) ^ (mc_u64)(mc_usize)(void *)state;
		if (s == 0) s = 0x123456789abcdef0ull;
	}
	*state = s;
}

enum dir {
	DIR_UP = 0,
	DIR_RIGHT = 1,
	DIR_DOWN = 2,
	DIR_LEFT = 3,
};

struct pt {
	mc_i32 x;
	mc_i32 y;
};

static int pt_eq_xy(mc_i32 ax, mc_i32 ay, mc_i32 bx, mc_i32 by) {
	return ax == bx && ay == by;
}

static int snake_contains_xy(const struct pt *snake, mc_i32 len, mc_i32 x, mc_i32 y) {
	for (mc_i32 i = 0; i < len; i++) {
		if (pt_eq_xy(snake[i].x, snake[i].y, x, y)) return 1;
	}
	return 0;
}

static void random_empty_cell(mc_u64 *rng, const struct pt *snake, mc_i32 snake_len, mc_i32 w, mc_i32 h, struct pt *out) {
	for (mc_i32 tries = 0; tries < 2000; tries++) {
		mc_u32 r = rng_next_u32(rng);
		mc_i32 x = (mc_i32)(r % (mc_u32)w);
		mc_i32 y = (mc_i32)((r / (mc_u32)w) % (mc_u32)h);
		if (!snake_contains_xy(snake, snake_len, x, y)) {
			out->x = x;
			out->y = y;
			return;
		}
	}
	for (mc_i32 y = 0; y < h; y++) {
		for (mc_i32 x = 0; x < w; x++) {
			if (!snake_contains_xy(snake, snake_len, x, y)) {
				out->x = x;
				out->y = y;
				return;
			}
		}
	}
	out->x = 0;
	out->y = 0;
}

static int read_key_nonblock(enum dir *io_dir, int *io_quit) {
	mc_u8 b[16];
	mc_i64 n = mc_sys_read(0, b, sizeof(b));
	if (n < 0) {
		if ((mc_u64)(-n) == (mc_u64)MC_EAGAIN || (mc_u64)(-n) == (mc_u64)MC_EINTR) return 0;
		return 0;
	}
	if (n == 0) return 0;

	for (mc_i64 i = 0; i < n; i++) {
		mc_u8 c = b[i];
		if (c == 'q' || c == 'Q') {
			*io_quit = 1;
			return 1;
		}
		if (c == 'w' || c == 'W') *io_dir = DIR_UP;
		else if (c == 's' || c == 'S') *io_dir = DIR_DOWN;
		else if (c == 'a' || c == 'A') *io_dir = DIR_LEFT;
		else if (c == 'd' || c == 'D') *io_dir = DIR_RIGHT;
		else if (c == 0x1b) {
			// arrow keys: ESC [ A/B/C/D
			if (i + 2 < n && b[i + 1] == '[') {
				mc_u8 k = b[i + 2];
				if (k == 'A') *io_dir = DIR_UP;
				else if (k == 'B') *io_dir = DIR_DOWN;
				else if (k == 'C') *io_dir = DIR_RIGHT;
				else if (k == 'D') *io_dir = DIR_LEFT;
				i += 2;
			}
		}
	}
	return 1;
}

struct input_state {
	mc_u8 esc_buf[8];
	mc_u32 esc_len;
};

static void input_state_reset(struct input_state *st) {
	st->esc_len = 0;
}

static void input_feed_byte(struct input_state *st, mc_u8 c, enum dir *io_dir, int *io_quit, int *io_pause_toggle) {
	if (st->esc_len == 0) {
		if (c == 0x1b) {
			st->esc_buf[st->esc_len++] = c;
			return;
		}
		if (c == 'q' || c == 'Q') {
			*io_quit = 1;
			return;
		}
		if (c == ' ') {
			*io_pause_toggle = 1;
			return;
		}
		if (c == 'w' || c == 'W') *io_dir = DIR_UP;
		else if (c == 's' || c == 'S') *io_dir = DIR_DOWN;
		else if (c == 'a' || c == 'A') *io_dir = DIR_LEFT;
		else if (c == 'd' || c == 'D') *io_dir = DIR_RIGHT;
		return;
	}

	// We are in an escape sequence.
	if (st->esc_len < (mc_u32)sizeof(st->esc_buf)) {
		st->esc_buf[st->esc_len++] = c;
	} else {
		input_state_reset(st);
		return;
	}

	// Supported sequences:
	//   ESC [ A/B/C/D  (arrow keys)
	//   ESC O A/B/C/D  (some terminals)
	if (st->esc_len == 3) {
		mc_u8 a = st->esc_buf[0];
		mc_u8 b = st->esc_buf[1];
		mc_u8 d = st->esc_buf[2];
		if (a == 0x1b && (b == '[' || b == 'O')) {
			if (d == 'A') *io_dir = DIR_UP;
			else if (d == 'B') *io_dir = DIR_DOWN;
			else if (d == 'C') *io_dir = DIR_RIGHT;
			else if (d == 'D') *io_dir = DIR_LEFT;
			input_state_reset(st);
			return;
		}
		input_state_reset(st);
		return;
	}

	// If it's not a known prefix, drop it.
	if (st->esc_len == 2) {
		if (st->esc_buf[0] == 0x1b && (st->esc_buf[1] == '[' || st->esc_buf[1] == 'O')) return;
		input_state_reset(st);
		return;
	}
}

static void draw_frame(const char *argv0, mc_i32 w, mc_i32 h, const struct pt *snake, mc_i32 snake_len, mc_i32 apple_x, mc_i32 apple_y,
	mc_i32 score, int paused) {
	write_str_or_die(argv0, "\x1b[H");
	write_str_or_die(argv0, "Snake  score=");
	(void)mc_write_u64_dec(1, (mc_u64)score);
	write_str_or_die(argv0, "  (arrows/WASD)  space=pause  q=quit");
	if (paused) write_str_or_die(argv0, "  PAUSED");
	write_str_or_die(argv0, "\r\n");

	// top border
	write_str_or_die(argv0, "+");
	for (mc_i32 x = 0; x < w * 2; x++) write_str_or_die(argv0, "-");
	write_str_or_die(argv0, "+\r\n");

	for (mc_i32 y = 0; y < h; y++) {
		write_str_or_die(argv0, "|");
		for (mc_i32 x = 0; x < w; x++) {
			char ch = ' ';
			if (pt_eq_xy(x, y, apple_x, apple_y)) ch = '*';
			for (mc_i32 i = 0; i < snake_len; i++) {
				if (pt_eq_xy(snake[i].x, snake[i].y, x, y)) {
					ch = (i == 0) ? 'O' : 'o';
					break;
				}
			}
			// Each logical cell is 2 columns wide. To avoid a "fat" snake, draw
			// content as "<glyph><space>" (and empty as two spaces).
			char a = ch;
			char b = ' ';
			if (a == ' ') {
				// empty cell
				write_all_or_die(argv0, "  ", 2);
			} else {
				write_all_or_die(argv0, &a, 1);
				write_all_or_die(argv0, &b, 1);
			}
		}
		write_str_or_die(argv0, "|\r\n");
	}

	// bottom border
	write_str_or_die(argv0, "+");
	for (mc_i32 x = 0; x < w * 2; x++) write_str_or_die(argv0, "-");
	write_str_or_die(argv0, "+\r\n");
}

__attribute__((used)) int main(int argc, char **argv, char **envp) {
	(void)envp;
	const char *argv0 = (argc > 0 && argv && argv[0]) ? argv[0] : "snake";

	mc_i32 cols = 80;
	mc_i32 rows = 24;
	query_terminal_size(&cols, &rows);

	mc_i32 w = 40;
	mc_i32 h = 15;
	if (!compute_board_size(cols, rows, &w, &h)) {
		w = 40;
		h = 15;
	}

	// Set stdin nonblocking for smooth polling.
	mc_i64 fl = mc_sys_fcntl(0, MC_F_GETFL, 0);
	if (fl < 0) mc_die_errno(argv0, "fcntl", fl);
	mc_i64 r = mc_sys_fcntl(0, MC_F_SETFL, (mc_i64)((mc_u64)fl | (mc_u64)MC_O_NONBLOCK));
	if (r < 0) mc_die_errno(argv0, "fcntl", r);

	int have_raw = enable_raw_terminal(argv0);
	(void)have_raw;
	ansi_enter_game(argv0);

	mc_u64 rng;
	rng_seed(&rng);

	mc_i32 max_cells = w * h;
	struct pt snake_buf[60 * 25];
	struct pt *snake = snake_buf;
	mc_i32 snake_len = 3;

	struct pt head;
	head.x = w / 2;
	head.y = h / 2;
	snake[0] = head;
	snake[1].x = head.x - 1;
	snake[1].y = head.y;
	snake[2].x = head.x - 2;
	snake[2].y = head.y;

	enum dir dir = DIR_RIGHT;
	struct pt apple;
	random_empty_cell(&rng, snake, snake_len, w, h, &apple);
	mc_i32 score = 0;
	int quit = 0;
	int paused = 0;
	struct input_state ist;
	input_state_reset(&ist);

	mc_i32 tick_ms = 110;

	while (!quit) {
		// adapt to terminal resize
		mc_i32 ncols = cols;
		mc_i32 nrows = rows;
		query_terminal_size(&ncols, &nrows);
		mc_i32 nw = w;
		mc_i32 nh = h;
		int ok_size = compute_board_size(ncols, nrows, &nw, &nh);
		if (!ok_size) {
			write_str_or_die(argv0, "\x1b[H\x1b[2J");
				write_str_or_die(argv0, "Terminal too small for snake. Resize the window or press q to quit.\r\n");
			// wait a bit and still allow quit
			struct mc_pollfd pf;
			pf.fd = 0;
			pf.events = MC_POLLIN;
			pf.revents = 0;
			(void)mc_sys_poll(&pf, 1, 200);
			mc_u8 b[32];
			mc_i64 nr = mc_sys_read(0, b, sizeof(b));
			if (nr > 0) {
				for (mc_i64 k = 0; k < nr; k++) {
					int pause_toggle = 0;
					input_feed_byte(&ist, b[k], &dir, &quit, &pause_toggle);
				}
			}
			continue;
		}
		if (nw != w || nh != h || ncols != cols || nrows != rows) {
			cols = ncols;
			rows = nrows;
			w = nw;
			h = nh;
			max_cells = w * h;
			// restart on resize (simpler/robust)
			snake_len = 3;
			head.x = w / 2;
			head.y = h / 2;
			snake[0] = head;
			snake[1].x = head.x - 1;
			snake[1].y = head.y;
			snake[2].x = head.x - 2;
			snake[2].y = head.y;
			dir = DIR_RIGHT;
			score = 0;
			paused = 0;
			tick_ms = 110;
			random_empty_cell(&rng, snake, snake_len, w, h, &apple);
			write_str_or_die(argv0, "\x1b[2J");
		}

		// poll stdin for up to tick
		struct mc_pollfd pfd;
		pfd.fd = 0;
		pfd.events = MC_POLLIN;
		pfd.revents = 0;
		mc_i64 pr = mc_sys_poll(&pfd, 1, tick_ms);
		if (pr < 0) {
			if ((mc_u64)(-pr) != (mc_u64)MC_EINTR) mc_die_errno(argv0, "poll", pr);
		}
		if (pr > 0 && (pfd.revents & MC_POLLIN)) {
			for (;;) {
				mc_u8 b[64];
				mc_i64 n = mc_sys_read(0, b, sizeof(b));
				if (n < 0) {
					mc_u64 e = (mc_u64)(-n);
					if (e == (mc_u64)MC_EAGAIN || e == (mc_u64)MC_EINTR) break;
					mc_die_errno(argv0, "read", n);
				}
				if (n == 0) break;
				for (mc_i64 k = 0; k < n; k++) {
					int pause_toggle = 0;
					input_feed_byte(&ist, b[k], &dir, &quit, &pause_toggle);
					if (pause_toggle) paused = !paused;
				}
			}
		}

		// prevent instant reverse
		// (if reversed, ignore by snapping back)
		// handle below by checking next head against snake[1]

		if (!paused && !quit) {
			struct pt next = snake[0];
			if (dir == DIR_UP) next.y--;
			else if (dir == DIR_DOWN) next.y++;
			else if (dir == DIR_LEFT) next.x--;
			else if (dir == DIR_RIGHT) next.x++;

			if (snake_len >= 2 && pt_eq_xy(next.x, next.y, snake[1].x, snake[1].y)) {
				// ignore reverse: continue forward
				next = snake[0];
				if (dir == DIR_UP) next.y++;
				else if (dir == DIR_DOWN) next.y--;
				else if (dir == DIR_LEFT) next.x++;
				else if (dir == DIR_RIGHT) next.x--;
			}

			// wrap edges
			if (next.x < 0) next.x = w - 1;
			if (next.x >= w) next.x = 0;
			if (next.y < 0) next.y = h - 1;
			if (next.y >= h) next.y = 0;

			int hit = snake_contains_xy(snake, snake_len, next.x, next.y);
			if (hit) {
				draw_frame(argv0, w, h, snake, snake_len, apple.x, apple.y, score, paused);
				write_str_or_die(argv0, "Game over! press q to quit\r\n");
				for (;;) {
					struct mc_pollfd pf;
					pf.fd = 0;
					pf.events = MC_POLLIN;
					pf.revents = 0;
					(void)mc_sys_poll(&pf, 1, 1000);
					int q3 = 0;
					enum dir tmpdir = dir;
					(void)read_key_nonblock(&tmpdir, &q3);
					if (q3) break;
				}
				break;
			}

			int grow = pt_eq_xy(next.x, next.y, apple.x, apple.y);
			// shift body
			for (mc_i32 i = snake_len - 1; i > 0; i--) {
				snake[i] = snake[i - 1];
			}
			snake[0] = next;
			if (grow) {
				score++;
				if (snake_len < max_cells) {
					snake[snake_len] = snake[snake_len - 1];
					snake_len++;
				}
				random_empty_cell(&rng, snake, snake_len, w, h, &apple);
				if (tick_ms > 45) tick_ms -= 2;
			}
		}

		draw_frame(argv0, w, h, snake, snake_len, apple.x, apple.y, score, paused);
	}

	ansi_leave_game(argv0);
	restore_terminal_best_effort();

	// restore stdin flags
	(void)mc_sys_fcntl(0, MC_F_SETFL, fl);
	return 0;
}
