#include "mc.h"

#include "mc_net.h"

#include "masto/masto_http.h"
#include "masto/masto_json.h"
#include "masto/masto_html.h"
#include "masto/masto_url.h"

static MC_NORETURN void die_usage(const char *argv0) {
	mc_die_usage(
		argv0,
		"masto [-i HOST|--instance HOST] <ping|instance|raw PATH|public|home|notif|post|interactive> ...\n"
		"  env: TOKEN=... (for home/notif/post), INSTANCE=...\n"
		"  public: [-r] [-n N]\n"
		"  home: [-n N]\n"
		"  notif: [-n N]\n"
		"  post: [-u|-p|-d] [-s SPOILER] TEXT...\n"
		"  interactive: [-n N] [-t SECONDS]"
	);
}

static void print_str(const char *s) {
	(void)mc_write_str(1, s);
}

static void print_nl(void) {
	(void)mc_write_str(1, "\n");
}

static void print_u64(mc_u64 v) {
	char buf[32];
	if (mc_snprint_cstr_u64_cstr(buf, sizeof(buf), "", v, "") > 0) {
		print_str(buf);
	}
}

static int buf_append(char *out, mc_usize out_cap, mc_usize *io_len, const char *s) {
	if (!out || out_cap == 0 || !io_len) return 1;
	if (!s) s = "";
	mc_usize n = mc_strlen(s);
	if (*io_len + n + 1u > out_cap) return 1;
	mc_memcpy(out + *io_len, s, n);
	*io_len += n;
	out[*io_len] = 0;
	return 0;
}

static const char *get_env(const char *key_eq) {
	// monacc-built tools don't reliably populate mc_get_start_envp(), so read
	// from /proc/self/environ (NUL-separated KEY=VALUE entries).
	static char envbuf[32768];
	static mc_usize envlen;
	static int loaded;

	if (!loaded) {
		loaded = 1;
		envlen = 0;
		mc_i64 fd = mc_sys_openat(MC_AT_FDCWD, "/proc/self/environ", MC_O_RDONLY | MC_O_CLOEXEC, 0);
		if (fd >= 0) {
			mc_i64 r = mc_sys_read((mc_i32)fd, envbuf, sizeof(envbuf) - 1u);
			if (r > 0) {
				envlen = (mc_usize)r;
				envbuf[envlen] = 0;
			}
			mc_sys_close((mc_i32)fd);
		}
	}

	if (!key_eq) return MC_NULL;
	mc_usize kn = mc_strlen(key_eq);
	mc_usize i = 0;
	while (i < envlen) {
		const char *e = envbuf + i;
		mc_usize rem = envlen - i;
		// Find NUL terminator (or end).
		mc_usize j = 0;
		while (j < rem && e[j] != 0) j++;
		if (j >= kn && mc_starts_with_n(e, key_eq, kn)) {
			return e + kn;
		}
		i += j + 1u;
	}
	return MC_NULL;
}

// ioctl constants (Linux).
#define MASTO_TIOCGWINSZ 0x5413u
// termios
#define MASTO_TCGETS 0x5401u
#define MASTO_TCSETS 0x5402u

#define MASTO_ICANON 0000002u
#define MASTO_ECHO   0000010u

#define MASTO_VTIME 5
#define MASTO_VMIN  6

#define MASTO_SIGINT 2

struct masto_winsize {
	mc_u16 ws_row;
	mc_u16 ws_col;
	mc_u16 ws_xpixel;
	mc_u16 ws_ypixel;
};

typedef mc_u32 masto_tcflag_t;
typedef mc_u8 masto_cc_t;
typedef mc_u32 masto_speed_t;

struct masto_termios {
	masto_tcflag_t c_iflag;
	masto_tcflag_t c_oflag;
	masto_tcflag_t c_cflag;
	masto_tcflag_t c_lflag;
	masto_cc_t c_line;
	masto_cc_t c_cc[19];
	masto_speed_t c_ispeed;
	masto_speed_t c_ospeed;
};

static struct masto_termios g_saved_term;
static int g_have_saved_term;
static volatile mc_i32 g_got_sigint;

static void restore_tty(void) {
	if (!g_have_saved_term) return;
	(void)mc_sys_ioctl(0, MASTO_TCSETS, &g_saved_term);
}

static void sigint_handler(int signum) {
	(void)signum;
	// Async-signal-safe: only set a flag.
	g_got_sigint = 1;
}

static void install_sigint_handler(void) {
	struct mc_sigaction sa;
	mc_memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigint_handler;
	sa.sa_flags = 0;
	(void)mc_sys_rt_sigaction(MASTO_SIGINT, &sa, MC_NULL, sizeof(sa.sa_mask));
}

static int enter_raw_mode(void) {
	struct masto_termios t;
	if (mc_sys_ioctl(0, MASTO_TCGETS, &t) != 0) return 1;
	g_saved_term = t;
	g_have_saved_term = 1;
	t.c_lflag &= ~((masto_tcflag_t)(MASTO_ICANON | MASTO_ECHO));
	t.c_cc[MASTO_VMIN] = 1;
	t.c_cc[MASTO_VTIME] = 0;
	if (mc_sys_ioctl(0, MASTO_TCSETS, &t) != 0) return 1;
	return 0;
}

static void ansi_clear(void) {
	// Clear screen and move cursor home.
	print_str("\033[2J\033[H");
}

static void ansi_clear_line(void) {
	print_str("\033[2K");
}

static void ansi_goto(mc_u16 row, mc_u16 col) {
	// 1-based.
	if (row == 0) row = 1;
	if (col == 0) col = 1;
	char a[32];
	char b[32];
	if (mc_snprint_cstr_u64_cstr(a, sizeof(a), "\033[", (mc_u64)row, ";") <= 0) return;
	if (mc_snprint_cstr_u64_cstr(b, sizeof(b), "", (mc_u64)col, "H") <= 0) return;
	print_str(a);
	print_str(b);
}

static void ansi_hide_cursor(void) {
	print_str("\033[?25l");
}

static void ansi_show_cursor(void) {
	print_str("\033[?25h");
}

static void ansi_rev_on(void) {
	print_str("\033[7m");
}

static void ansi_rev_off(void) {
	print_str("\033[0m");
}

static void print_repeat(char c, mc_usize n) {
	char buf[256];
	if (n == 0) {
		print_nl();
		return;
	}
	if (n > 4096u) n = 4096u;
	for (mc_usize i = 0; i < sizeof(buf); i++) buf[i] = c;
	while (n) {
		mc_usize take = n;
		if (take > sizeof(buf)) take = sizeof(buf);
		(void)mc_sys_write(1, buf, take);
		n -= take;
	}
	print_nl();
}

static void print_hr(mc_u16 cols) {
	// ASCII line so column count is predictable.
	mc_usize n = (cols ? (mc_usize)cols : 80u);
	print_repeat('-', n);
}

static void calc_layout(mc_u16 rows, mc_usize *out_content_lines, mc_usize *out_card_h, mc_usize *out_page) {
	// Layout:
	//  row 1: header
	//  row 2: hr
	//  row N: status bar
	//  middle rows: cards
	if (out_content_lines) *out_content_lines = 3;
	if (out_card_h) *out_card_h = 6;
	if (out_page) *out_page = 1;

	mc_usize avail_rows = (rows > 3 ? (mc_usize)rows - 3u : 0u);
	if (avail_rows == 0) {
		if (out_content_lines) *out_content_lines = 1;
		if (out_card_h) *out_card_h = 4;
		if (out_page) *out_page = 1;
		return;
	}

	// Keep cards compact so larger terminals show more posts.
	// card_h = 2 header lines + content_lines + 1 hr
	mc_usize content_lines = 2u;
	if (avail_rows < 10u) content_lines = 1u;
	if (avail_rows > 50u) content_lines = 3u;
	mc_usize card_h = 3u + content_lines;

	mc_usize page = avail_rows / card_h;
	if (page < 1u) page = 1u;

	if (out_content_lines) *out_content_lines = content_lines;
	if (out_card_h) *out_card_h = card_h;
	if (out_page) *out_page = page;
}

static void clamp_nav(mc_usize item_count, mc_usize *io_top, mc_usize *io_sel) {
	mc_usize top = io_top ? *io_top : 0;
	mc_usize sel = io_sel ? *io_sel : 0;
	if (item_count == 0) {
		if (io_top) *io_top = 0;
		if (io_sel) *io_sel = 0;
		return;
	}
	if (sel >= item_count) sel = item_count - 1u;
	if (top >= item_count) top = 0;
	if (top > sel) top = sel;
	if (io_top) *io_top = top;
	if (io_sel) *io_sel = sel;
}

static void get_term_size(mc_u16 *out_cols, mc_u16 *out_rows) {
	mc_u16 cols = 80;
	mc_u16 rows = 24;
	struct masto_winsize ws;
	ws.ws_row = 0;
	ws.ws_col = 0;
	ws.ws_xpixel = 0;
	ws.ws_ypixel = 0;
	if (mc_sys_ioctl(1, MASTO_TIOCGWINSZ, &ws) == 0) {
		if (ws.ws_col) cols = ws.ws_col;
		if (ws.ws_row) rows = ws.ws_row;
	}
	if (out_cols) *out_cols = cols;
	if (out_rows) *out_rows = rows;
}

static mc_usize write_wrapped(const char *s, mc_usize width, mc_usize max_lines) {
	if (!s) return 0;
	if (width < 10) width = 10;
	if (width > 240) width = 240;

	char line[256];
	if (width >= sizeof(line)) width = sizeof(line) - 1u;

	mc_usize lines = 0;
	mc_usize i = 0;
	while (s[i] && lines < max_lines) {
		mc_usize len = 0;
		mc_usize last_space = (mc_usize)-1;
		// Consume leading spaces.
		while (s[i] == ' ' || s[i] == '\t') i++;
		while (s[i] && s[i] != '\n' && len < width) {
			line[len] = s[i];
			if (line[len] == ' ') last_space = len;
			len++;
			i++;
		}
		if (s[i] && s[i] != '\n' && len == width) {
			// If we hit width mid-word, wrap on last space.
			if (last_space != (mc_usize)-1 && last_space > 0 && last_space + 1u < len) {
				mc_usize rollback = len - (last_space + 1u);
				i -= rollback;
				len = last_space;
			}
			// Skip spaces after wrap.
			while (s[i] == ' ' || s[i] == '\t') i++;
		}
		// Trim trailing spaces.
		while (len && (line[len - 1u] == ' ' || line[len - 1u] == '\t')) len--;
		line[len] = 0;
		print_str(line);
		print_nl();
		lines++;
		if (s[i] == '\n') i++;
	}
	return lines;
}

static int skip_ws(const char *s, mc_usize *io) {
	if (!s || !io) return 1;
	mc_usize i = *io;
	while (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') i++;
	*io = i;
	return 0;
}

static int content_has_more(const char *s, mc_usize i) {
	if (!s) return 0;
	while (s[i]) {
		char c = s[i];
		if (c != ' ' && c != '\t' && c != '\n' && c != '\r') return 1;
		i++;
	}
	return 0;
}

struct masto_item {
	char id[32];
	char created_at[64];
	char acct[128];
	char display_name[256];
	char boosted_by[128];
	char content_txt[2048];
	mc_u64 reblogs;
	mc_u64 favs;
	mc_u64 replies;
};

#define MASTO_MAX_ITEMS 64
static struct masto_item g_items[MASTO_MAX_ITEMS];
static mc_usize g_item_count;

static void item_zero(struct masto_item *it) {
	if (!it) return;
	it->id[0] = 0;
	it->created_at[0] = 0;
	it->acct[0] = 0;
	it->display_name[0] = 0;
	it->boosted_by[0] = 0;
	it->content_txt[0] = 0;
	it->reblogs = 0;
	it->favs = 0;
	it->replies = 0;
}

static void format_when(const char *created_at, char *out, mc_usize out_cap) {
	// Mastodon uses RFC3339-like: 2025-12-21T00:00:00.000Z
	// Format compact: YYYY-MM-DD HH:MM
	if (!out || out_cap == 0) return;
	out[0] = 0;
	if (!created_at || !*created_at) return;
	char tmp[32];
	tmp[0] = 0;
	mc_usize n = mc_strlen(created_at);
	if (n > 16u) n = 16u;
	if (n + 1u > sizeof(tmp)) n = sizeof(tmp) - 1u;
	mc_memcpy(tmp, created_at, n);
	tmp[n] = 0;
	for (mc_usize i = 0; tmp[i]; i++) {
		if (tmp[i] == 'T') tmp[i] = ' ';
	}
	(void)mc_snprint_cstr_cstr(out, out_cap, "", tmp);
}

static int parse_status_item(const char *obj, mc_usize obj_len, struct masto_item *out) {
	if (!obj || obj_len == 0 || !out) return 1;
	item_zero(out);

	// Handle boosts: if there's a reblog object, parse that as the status content,
	// but keep a small "boosted by" hint from the wrapper account.
	const char *status_obj = obj;
	mc_usize status_len = obj_len;
	{
		const char *reblog_obj = MC_NULL;
		mc_usize reblog_len = 0;
		if (masto_json_find_object_field(obj, obj_len, "reblog", &reblog_obj, &reblog_len) == 0) {
			status_obj = reblog_obj;
			status_len = reblog_len;
			const char *wrap_acct_obj = MC_NULL;
			mc_usize wrap_acct_obj_len = 0;
			if (masto_json_find_object_field(obj, obj_len, "account", &wrap_acct_obj, &wrap_acct_obj_len) == 0) {
				(void)masto_json_get_string_field(wrap_acct_obj, wrap_acct_obj_len, "acct", out->boosted_by, sizeof(out->boosted_by));
			}
		}
	}

	char content_html[4096];
	content_html[0] = 0;
	(void)masto_json_get_string_field(status_obj, status_len, "id", out->id, sizeof(out->id));
	(void)masto_json_get_string_field(status_obj, status_len, "created_at", out->created_at, sizeof(out->created_at));
	(void)masto_json_get_string_field(status_obj, status_len, "content", content_html, sizeof(content_html));
	(void)masto_json_get_u64_field(status_obj, status_len, "reblogs_count", &out->reblogs);
	(void)masto_json_get_u64_field(status_obj, status_len, "favourites_count", &out->favs);
	(void)masto_json_get_u64_field(status_obj, status_len, "replies_count", &out->replies);

	const char *acct_obj = MC_NULL;
	mc_usize acct_obj_len = 0;
	if (masto_json_find_object_field(status_obj, status_len, "account", &acct_obj, &acct_obj_len) == 0) {
		(void)masto_json_get_string_field(acct_obj, acct_obj_len, "acct", out->acct, sizeof(out->acct));
		(void)masto_json_get_string_field(acct_obj, acct_obj_len, "display_name", out->display_name, sizeof(out->display_name));
	}

	masto_html_strip(content_html, mc_strlen(content_html), out->content_txt, sizeof(out->content_txt));
	return 0;
}

static mc_usize parse_timeline_array(const char *json, mc_usize json_len, struct masto_item *out_items, mc_usize out_cap) {
	if (!json || json_len == 0 || !out_items || out_cap == 0) return 0;
	mc_usize pos = 0;
	mc_usize n = 0;
	for (; n < out_cap; n++) {
		const char *obj = MC_NULL;
		mc_usize obj_len = 0;
		if (masto_json_next_object_in_array(json, json_len, &pos, &obj, &obj_len) != 0) break;
		if (parse_status_item(obj, obj_len, &out_items[n]) != 0) {
			item_zero(&out_items[n]);
		}
	}
	return n;
}

static void render_items_page(const char *instance, mc_u16 cols, mc_u16 rows, mc_usize new_count, const char *msg, mc_usize top, mc_usize sel) {
	ansi_clear();

	char hdr[256];
	hdr[0] = 0;
	(void)mc_snprint_cstr_cstr(hdr, sizeof(hdr), "Home — ", instance ? instance : "?");
	print_str(hdr);
	if (new_count) {
		print_str("  (+");
		print_u64((mc_u64)new_count);
		print_str(")");
	}
	if (msg && *msg) {
		print_str("  ");
		print_str(msg);
	}
	print_nl();
	print_hr(cols);

	// Fixed-height card layout so scrolling is predictable.
	mc_usize content_lines = 3;
	mc_usize card_h = 6;
	mc_usize page = 1;
	calc_layout(rows, &content_lines, &card_h, &page);

	if (top >= g_item_count) top = 0;
	if (sel >= g_item_count && g_item_count) sel = g_item_count - 1u;

	for (mc_usize pi = 0; pi < page; pi++) {
		mc_usize idx = top + pi;
		if (idx >= g_item_count) break;
		struct masto_item *it = &g_items[idx];
		int selected = (idx == sel);

		if (selected) ansi_rev_on();
		print_str(selected ? "> " : "  ");
		if (it->display_name[0]) {
			print_str(it->display_name);
			print_str(" (@");
			print_str(it->acct[0] ? it->acct : "?");
			print_str(")\n");
		} else {
			print_str("@");
			print_str(it->acct[0] ? it->acct : "?");
			print_nl();
		}

		char when[64];
		when[0] = 0;
		format_when(it->created_at, when, sizeof(when));
		print_str(selected ? "> " : "  ");
		print_str(when[0] ? when : (it->created_at[0] ? it->created_at : "?"));
		if (it->boosted_by[0]) {
			print_str("  boosted by @");
			print_str(it->boosted_by);
		}
		print_str("   B:");
		print_u64(it->reblogs);
		print_str(" F:");
		print_u64(it->favs);
		print_str(" R:");
		print_u64(it->replies);
		print_nl();
		if (selected) ansi_rev_off();

		// Content (indented, wrapped, limited).
		const char *content = it->content_txt[0] ? it->content_txt : "(no text content)";
		mc_usize width = (cols > 4 ? (mc_usize)cols - 2u : 20u);
		mc_usize ci = 0;
		for (mc_usize li = 0; li < content_lines; li++) {
			skip_ws(content, &ci);
			if (!content[ci]) {
				print_str("  \n");
				continue;
			}
			// Print one wrapped line into a temp buffer.
			char tmp[256];
			mc_usize w = width;
			if (w >= sizeof(tmp)) w = sizeof(tmp) - 1u;
			mc_usize len = 0;
			mc_usize last_space = (mc_usize)-1;
			while (content[ci] && content[ci] != '\n' && len < w) {
				tmp[len] = content[ci];
				if (tmp[len] == ' ') last_space = len;
				len++;
				ci++;
			}
			if (content[ci] && content[ci] != '\n' && len == w) {
				if (last_space != (mc_usize)-1 && last_space > 0 && last_space + 1u < len) {
					mc_usize rollback = len - (last_space + 1u);
					ci -= rollback;
					len = last_space;
				}
			}
			while (len && (tmp[len - 1u] == ' ' || tmp[len - 1u] == '\t')) len--;
			tmp[len] = 0;
			print_str("  ");
			print_str(tmp);
			print_nl();
			if (content[ci] == '\n') ci++;
		}
		if (content_has_more(content, ci)) {
			print_str("  …\n");
		}
		print_hr(cols);
	}

	// Status bar (bottom line)
	ansi_goto(rows, 1);
	ansi_rev_on();
	ansi_clear_line();
	print_str("q quit  p post  Up/Down move  Left reply");
	print_str("  |  ");
	mc_usize shown_first = 0;
	mc_usize shown_last = 0;
	if (g_item_count) {
		shown_first = top + 1u;
		shown_last = top + page;
		if (shown_last > g_item_count) shown_last = g_item_count;
	}
	print_str("show ");
	print_u64((mc_u64)shown_first);
	print_str("-");
	print_u64((mc_u64)shown_last);
	print_str(" of ");
	print_u64((mc_u64)g_item_count);
	print_str("  |  ");
	print_str("sel ");
	print_u64((mc_u64)(g_item_count ? (sel + 1u) : 0u));
	print_str("/");
	print_u64((mc_u64)g_item_count);
	print_str("  top ");
	print_u64((mc_u64)top);
	ansi_rev_off();
}

static void drain_to_eol(void) {
	// In canonical mode, when we read a single character for a command,
	// the rest of the line (including '\n') may still be buffered.
	for (;;) {
		char c;
		mc_i64 rn = mc_sys_read(0, &c, 1);
		if (rn != 1) return;
		if (c == '\n') return;
	}
}

static int read_line_into(char *out, mc_usize out_cap) {
	if (!out || out_cap == 0) return 1;
	out[0] = 0;
	mc_usize o = 0;
	for (;;) {
		char c;
		mc_i64 rn = mc_sys_read(0, &c, 1);
		if (rn != 1) break;
		if (c == '\r') continue;
		if (c == '\n') break;
		if (o + 1u < out_cap) out[o++] = c;
	}
	out[o] = 0;
	return (o == 0) ? 1 : 0;
}

enum masto_key {
	KEY_NONE = 0,
	KEY_UP,
	KEY_DOWN,
	KEY_LEFT,
	KEY_RIGHT,
	KEY_ENTER,
	KEY_ESC,
	KEY_BACKSPACE,
	KEY_CHAR
};

static enum masto_key read_key(char *out_ch) {
	char c;
	mc_i64 rn = mc_sys_read(0, &c, 1);
	if (rn != 1) return KEY_NONE;
	if (out_ch) *out_ch = c;
	if (c == '\n' || c == '\r') return KEY_ENTER;
	if ((mc_u8)c == 0x1b) {
		// Escape sequence.
		char a;
		rn = mc_sys_read(0, &a, 1);
		if (rn != 1) return KEY_ESC;
		if (a != '[' && a != 'O') return KEY_ESC;
		char b;
		rn = mc_sys_read(0, &b, 1);
		if (rn != 1) return KEY_ESC;
		if (b == 'A') return KEY_UP;
		if (b == 'B') return KEY_DOWN;
		if (b == 'C') return KEY_RIGHT;
		if (b == 'D') return KEY_LEFT;
		return KEY_ESC;
	}
	if ((mc_u8)c == 0x7f || c == '\b') return KEY_BACKSPACE;
	return KEY_CHAR;
}

static int edit_line_raw(mc_u16 row, const char *prompt, char *buf, mc_usize cap, const char *initial) {
	if (!buf || cap == 0) return 1;
	buf[0] = 0;
	if (initial && *initial) {
		mc_usize n = mc_strlen(initial);
		if (n + 1u > cap) n = cap - 1u;
		mc_memcpy(buf, initial, n);
		buf[n] = 0;
	}
	for (;;) {
		ansi_goto(row, 1);
		ansi_clear_line();
		print_str(prompt ? prompt : "> ");
		print_str(buf);
		// Keep cursor at end (we only support append/backspace).
		char ch = 0;
		enum masto_key k = read_key(&ch);
		if (k == KEY_NONE) continue;
		if (k == KEY_ENTER) {
			return (buf[0] ? 0 : 1);
		}
		if (k == KEY_ESC) {
			buf[0] = 0;
			return 1;
		}
		if (k == KEY_BACKSPACE) {
			mc_usize n = mc_strlen(buf);
			if (n) buf[n - 1u] = 0;
			continue;
		}
		if (k == KEY_CHAR) {
			mc_u8 uc = (mc_u8)ch;
			if (uc >= 0x20 && uc != 0x7f) {
				mc_usize n = mc_strlen(buf);
				if (n + 1u < cap) {
					buf[n] = ch;
					buf[n + 1u] = 0;
				}
			}
			continue;
		}
	}
}

static int interactive_post_public(const char *argv0, const char *instance, const char *token, const char *text, char *msg, mc_usize msg_cap) {
	if (msg && msg_cap) msg[0] = 0;
	if (!token || !*token) return 1;
	if (!text || !*text) return 1;

	char enc[4096];
	if (masto_urlencode_form(text, enc, sizeof(enc)) != 0) {
		if (msg && msg_cap) (void)mc_snprint_cstr_cstr(msg, msg_cap, "post: ", "too long");
		return 1;
	}
	char form[8192];
	if (mc_snprint_cstr_cstr(form, sizeof(form), "status=", enc) <= 0) return 1;

	static char body[262144];
	mc_usize body_len = 0;
	mc_i32 status = 0;
	if (masto_http_request_body_status_via_tls13(
		argv0,
		instance,
		instance,
		"POST",
		"/api/v1/statuses",
		token,
		"application/x-www-form-urlencoded",
		form,
		mc_strlen(form),
		&status,
		body,
		sizeof(body),
		&body_len
	) != 0) {
		if (msg && msg_cap) (void)mc_snprint_cstr_cstr(msg, msg_cap, "post: ", "failed");
		return 1;
	}
	if (status < 200 || status > 299) {
		if (msg && msg_cap) {
			char sbuf[32];
			if (mc_snprint_cstr_i64_cstr(sbuf, sizeof(sbuf), "", (mc_i64)status, "") > 0) {
				char tmp[96];
				if (mc_snprint_cstr_cstr(tmp, sizeof(tmp), "post: http ", sbuf) > 0) {
					(void)mc_snprint_cstr_cstr(msg, msg_cap, "", tmp);
				}
			}
		}
		return 1;
	}

	char id[64];
	id[0] = 0;
	(void)masto_json_get_string_field(body, body_len, "id", id, sizeof(id));
	if (msg && msg_cap) {
		if (id[0]) {
			char tmp[96];
			if (mc_snprint_cstr_cstr(tmp, sizeof(tmp), "Posted id=", id) > 0) {
				(void)mc_snprint_cstr_cstr(msg, msg_cap, "", tmp);
			}
		} else {
			(void)mc_snprint_cstr_cstr(msg, msg_cap, "", "Posted");
		}
	}
	return 0;
}

static int interactive_post_reply(const char *argv0, const char *instance, const char *token, const char *text, const char *in_reply_to_id, char *msg, mc_usize msg_cap) {
	if (msg && msg_cap) msg[0] = 0;
	if (!token || !*token) return 1;
	if (!text || !*text) return 1;
	if (!in_reply_to_id || !*in_reply_to_id) return 1;

	char enc[4096];
	if (masto_urlencode_form(text, enc, sizeof(enc)) != 0) {
		if (msg && msg_cap) (void)mc_snprint_cstr_cstr(msg, msg_cap, "reply: ", "too long");
		return 1;
	}
	char enc_id[96];
	if (masto_urlencode_form(in_reply_to_id, enc_id, sizeof(enc_id)) != 0) return 1;

	char form[8192];
	form[0] = 0;
	mc_usize o = 0;
	if (buf_append(form, sizeof(form), &o, "status=") != 0) return 1;
	if (buf_append(form, sizeof(form), &o, enc) != 0) return 1;
	if (buf_append(form, sizeof(form), &o, "&in_reply_to_id=") != 0) return 1;
	if (buf_append(form, sizeof(form), &o, enc_id) != 0) return 1;

	static char body[262144];
	mc_usize body_len = 0;
	mc_i32 status = 0;
	if (masto_http_request_body_status_via_tls13(
		argv0,
		instance,
		instance,
		"POST",
		"/api/v1/statuses",
		token,
		"application/x-www-form-urlencoded",
		form,
		mc_strlen(form),
		&status,
		body,
		sizeof(body),
		&body_len
	) != 0) {
		if (msg && msg_cap) (void)mc_snprint_cstr_cstr(msg, msg_cap, "reply: ", "failed");
		return 1;
	}
	if (status < 200 || status > 299) {
		if (msg && msg_cap) {
			char sbuf[32];
			if (mc_snprint_cstr_i64_cstr(sbuf, sizeof(sbuf), "", (mc_i64)status, "") > 0) {
				char tmp[96];
				if (mc_snprint_cstr_cstr(tmp, sizeof(tmp), "reply: http ", sbuf) > 0) {
					(void)mc_snprint_cstr_cstr(msg, msg_cap, "", tmp);
				}
			}
		}
		return 1;
	}
	if (msg && msg_cap) (void)mc_snprint_cstr_cstr(msg, msg_cap, "", "Replied");
	return 0;
}

static int cmd_interactive(const char *argv0, const char *instance, const char *token, int argc, char **argv, int i) {
	mc_u64 n = 30;
	mc_u64 interval_s = 30;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "masto interactive -n N");
			mc_u64 tmp = 0;
			if (mc_parse_u64_dec(argv[++i], &tmp) != 0) mc_die_usage(argv0, "masto interactive -n N");
			n = tmp;
			if (n == 0) n = 1;
			if (n > MASTO_MAX_ITEMS) n = MASTO_MAX_ITEMS;
			continue;
		}
		if (mc_streq(a, "-t")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "masto interactive -t SECONDS");
			mc_u64 tmp = 0;
			if (mc_parse_u64_dec(argv[++i], &tmp) != 0) mc_die_usage(argv0, "masto interactive -t SECONDS");
			interval_s = tmp;
			if (interval_s < 5) interval_s = 5;
			if (interval_s > 300) interval_s = 300;
			continue;
		}
		mc_die_usage(argv0, "masto interactive [-n N] [-t SECONDS]");
	}

	if (!token || !*token) mc_die_usage(argv0, "TOKEN=... masto interactive");

	mc_u16 cols = 80;
	mc_u16 rows = 24;
	get_term_size(&cols, &rows);
	mc_u16 last_cols = cols;
	mc_u16 last_rows = rows;

	static char body[262144];
	static struct masto_item new_items[MASTO_MAX_ITEMS];
	char last_id[32];
	last_id[0] = 0;
	char flash[96];
	flash[0] = 0;

	ansi_hide_cursor();
	if (enter_raw_mode() != 0) {
		ansi_show_cursor();
		print_str("error: tty raw mode failed\n");
		return 1;
	}
	install_sigint_handler();

	// Initial fetch.
	{
		char path[256];
		if (mc_snprint_cstr_cstr_u64_cstr(path, sizeof(path), "/api/v1/timelines/home?limit=", "", n, "") <= 0) {
			restore_tty();
			ansi_show_cursor();
			return 1;
		}
		mc_usize body_len = 0;
		mc_i32 status = 0;
		if (masto_http_request_body_status_via_tls13(
			argv0,
			instance,
			instance,
			"GET",
			path,
			token,
			MC_NULL,
			MC_NULL,
			0,
			&status,
			body,
			sizeof(body),
			&body_len
		) != 0) {
			restore_tty();
			ansi_show_cursor();
			print_str("error: fetch failed\n");
			return 1;
		}
		if (status < 200 || status > 299) {
			restore_tty();
			ansi_show_cursor();
			print_str("error: http ");
			char sbuf[32];
			if (mc_snprint_cstr_i64_cstr(sbuf, sizeof(sbuf), "", (mc_i64)status, "") > 0) print_str(sbuf);
			print_nl();
			if (body_len) {
				mc_usize take = body_len;
				if (take > 512u) take = 512u;
				(void)mc_sys_write(1, body, take);
				print_nl();
			}
			return 1;
		}
		if (body_len == 0 || body[0] != '[') {
			restore_tty();
			ansi_show_cursor();
			print_str("error: unexpected response\n");
			return 1;
		}
		g_item_count = parse_timeline_array(body, body_len, g_items, (mc_usize)n);
		if (g_item_count && g_items[0].id[0]) {
			(void)mc_snprint_cstr_cstr(last_id, sizeof(last_id), "", g_items[0].id);
		}
		render_items_page(instance, cols, rows, 0, MC_NULL, 0, 0);
	}

	// Navigation state.
	mc_usize top = 0;
	mc_usize sel = 0;

	for (;;) {
		if (g_got_sigint) break;
		// Wait for keypress or refresh timeout.
		struct mc_pollfd pfd;
		pfd.fd = 0;
		pfd.events = MC_POLLIN;
		pfd.revents = 0;
		mc_i64 pr = mc_sys_poll(&pfd, 1, (mc_i32)(interval_s * 1000u));
		if (g_got_sigint) break;
		if (pr > 0 && (pfd.revents & MC_POLLIN)) {
			char ch = 0;
			enum masto_key k = read_key(&ch);
			// Apply resizes immediately for key-driven redraws.
			get_term_size(&cols, &rows);
			last_cols = cols;
			last_rows = rows;
			if (k == KEY_CHAR) {
				if (ch == 'q' || ch == 'Q') break;
				if (ch == 'p' || ch == 'P') {
					ansi_show_cursor();
					char line[4096];
					line[0] = 0;
					if (edit_line_raw(rows, "Post> ", line, sizeof(line), MC_NULL) == 0) {
						flash[0] = 0;
						(void)interactive_post_public(argv0, instance, token, line, flash, sizeof(flash));
					}
					ansi_hide_cursor();
					render_items_page(instance, cols, rows, 0, flash[0] ? flash : MC_NULL, top, sel);
					flash[0] = 0;
					continue;
				}
			}
			if (k == KEY_UP) {
				if (sel > 0) sel--;
				if (sel < top) top = sel;
				clamp_nav(g_item_count, &top, &sel);
				render_items_page(instance, cols, rows, 0, MC_NULL, top, sel);
				continue;
			}
			if (k == KEY_DOWN) {
				if (sel + 1u < g_item_count) sel++;
				// Scroll by whole cards (keep in sync with renderer).
				mc_usize content_lines = 3;
				mc_usize card_h = 6;
				mc_usize page = 1;
				calc_layout(rows, &content_lines, &card_h, &page);
				if (sel >= top + page) top = sel - page + 1u;
				clamp_nav(g_item_count, &top, &sel);
				render_items_page(instance, cols, rows, 0, MC_NULL, top, sel);
				continue;
			}
			if (k == KEY_LEFT) {
				clamp_nav(g_item_count, &top, &sel);
				if (sel < g_item_count) {
					struct masto_item *it = &g_items[sel];
					if (it->id[0]) {
						char initial[256];
						initial[0] = 0;
						if (it->acct[0]) {
							(void)mc_snprint_cstr_cstr(initial, sizeof(initial), "@", it->acct);
							// append space
							mc_usize o = mc_strlen(initial);
							if (o + 2u < sizeof(initial)) {
								initial[o] = ' ';
								initial[o + 1u] = 0;
							}
						}
						ansi_show_cursor();
						char line[4096];
						line[0] = 0;
						if (edit_line_raw(rows, "Reply> ", line, sizeof(line), initial[0] ? initial : MC_NULL) == 0) {
							flash[0] = 0;
							(void)interactive_post_reply(argv0, instance, token, line, it->id, flash, sizeof(flash));
						}
						ansi_hide_cursor();
						clamp_nav(g_item_count, &top, &sel);
						render_items_page(instance, cols, rows, 0, flash[0] ? flash : MC_NULL, top, sel);
						flash[0] = 0;
						continue;
					}
				}
				continue;
			}
			continue;
		}

		// Refresh (fetch only new items if we have an id).
		mc_usize new_count = 0;
		mc_u16 cur_cols = cols;
		mc_u16 cur_rows = rows;
		get_term_size(&cur_cols, &cur_rows);
		{
			char path[512];
			if (last_id[0]) {
				// Mastodon expects since_id as a string/integer.
				mc_usize o = 0;
				char p0[256];
				if (mc_snprint_cstr_cstr_u64_cstr(p0, sizeof(p0), "/api/v1/timelines/home?limit=", "", n, "") <= 0) break;
				if (buf_append(path, sizeof(path), &o, p0) != 0) break;
				if (buf_append(path, sizeof(path), &o, "&since_id=") != 0) break;
				if (buf_append(path, sizeof(path), &o, last_id) != 0) break;
			} else {
				if (mc_snprint_cstr_cstr_u64_cstr(path, sizeof(path), "/api/v1/timelines/home?limit=", "", n, "") <= 0) break;
			}
			mc_usize body_len = 0;
			mc_i32 status = 0;
			if (masto_http_request_body_status_via_tls13(
				argv0,
				instance,
				instance,
				"GET",
				path,
				token,
				MC_NULL,
				MC_NULL,
				0,
				&status,
				body,
				sizeof(body),
				&body_len
			) != 0) {
				// Keep old screen; try again next tick.
				continue;
			}
			if (status < 200 || status > 299) {
				// Keep old screen; try again next tick.
				continue;
			}
			if (body_len == 0 || body[0] != '[') {
				continue;
			}
			new_count = parse_timeline_array(body, body_len, new_items, (mc_usize)n);
		}

		if (new_count) {
			// Prepend new items.
			if (new_count > (mc_usize)n) new_count = (mc_usize)n;
			mc_usize keep_old = g_item_count;
			if (keep_old > (mc_usize)n) keep_old = (mc_usize)n;
			mc_usize max_keep = (mc_usize)n;
			if (new_count >= max_keep) {
				for (mc_usize k = 0; k < max_keep; k++) g_items[k] = new_items[k];
				g_item_count = max_keep;
			} else {
				mc_usize shift = new_count;
				mc_usize new_total = keep_old + shift;
				if (new_total > max_keep) new_total = max_keep;
				// Shift existing down.
				for (mc_usize k = new_total; k-- > shift; ) {
					g_items[k] = g_items[k - shift];
				}
				// Copy in new.
				for (mc_usize k = 0; k < shift; k++) g_items[k] = new_items[k];
				g_item_count = new_total;
			}
			if (g_item_count && g_items[0].id[0]) {
				(void)mc_snprint_cstr_cstr(last_id, sizeof(last_id), "", g_items[0].id);
			}
			cols = cur_cols;
			rows = cur_rows;
			last_cols = cols;
			last_rows = rows;
			// Keep selection on the same visible item by shifting it down.
			if (sel + new_count < g_item_count) sel += new_count;
			if (top + new_count < g_item_count) top += new_count;
			clamp_nav(g_item_count, &top, &sel);
			render_items_page(instance, cols, rows, new_count, MC_NULL, top, sel);
		} else {
			// No new items; redraw only on terminal resize.
			if (cur_cols != last_cols || cur_rows != last_rows) {
				cols = cur_cols;
				rows = cur_rows;
				last_cols = cols;
				last_rows = rows;
				clamp_nav(g_item_count, &top, &sel);
				render_items_page(instance, cols, rows, 0, MC_NULL, top, sel);
			}
		}
	}

	restore_tty();
	ansi_show_cursor();
	print_nl();
	if (g_got_sigint) return 130;
	return 0;
}

static int cmd_ping(const char *argv0, const char *instance) {
	// Establish a TLS 1.3 connection and do a tiny HTTPS request.
	static char body[65536];
	mc_usize body_len = 0;
	mc_i32 status = 0;
	if (masto_http_request_body_status_via_tls13(
		argv0,
		instance,
		instance,
		"GET",
		"/api/v2/instance",
		MC_NULL,
		MC_NULL,
		MC_NULL,
		0,
		&status,
		body,
		sizeof(body),
		&body_len
	) != 0) return 1;
	if (status < 200 || status > 299) return 1;
	print_str("ok: tls connected\n");
	return 0;
}

static int cmd_instance(const char *argv0, const char *instance) {
	static char body[32768];
	mc_usize body_len = 0;
	if (masto_http_get_body_via_tls13(argv0, instance, instance, "/api/v2/instance", body, sizeof(body), &body_len) != 0) {
		print_str("error: fetch failed\n");
		return 1;
	}

	char domain[128];
	char title[256];
	char version[64];
	domain[0] = 0;
	title[0] = 0;
	version[0] = 0;
	(void)masto_json_get_string_field(body, body_len, "domain", domain, sizeof(domain));
	(void)masto_json_get_string_field(body, body_len, "title", title, sizeof(title));
	(void)masto_json_get_string_field(body, body_len, "version", version, sizeof(version));

	print_str(domain[0] ? domain : instance);
	print_str("\n");
	if (title[0]) {
		print_str("title: ");
		print_str(title);
		print_nl();
	}
	if (version[0]) {
		print_str("version: ");
		print_str(version);
		print_nl();
	}
	return 0;
}

static int cmd_raw(const char *argv0, const char *instance, const char *path) {
	static char body[262144];
	mc_usize body_len = 0;
	if (masto_http_get_body_via_tls13(argv0, instance, instance, path, body, sizeof(body), &body_len) != 0) {
		print_str("error: fetch failed\n");
		return 1;
	}
	// `body` is NUL-terminated, but may contain newlines, HTML, JSON etc.
	(void)mc_sys_write(1, body, body_len);
	if (body_len == 0 || body[body_len - 1u] != '\n') print_nl();
	return 0;
}

static int cmd_public(const char *argv0, const char *instance, int argc, char **argv, int i) {
	// Defaults
	mc_u64 n = 20;
	int remote = 0;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "masto public -n N");
			{
				mc_u64 tmp = 0;
				if (mc_parse_u64_dec(argv[++i], &tmp) != 0) mc_die_usage(argv0, "masto public -n N");
				n = tmp;
			}
			if (n == 0) n = 1;
			if (n > 40) n = 40;
			continue;
		}
		if (mc_streq(a, "-r")) {
			remote = 1;
			continue;
		}
		mc_die_usage(argv0, "masto public [-n N] [-r]");
	}

	char path[256];
	if (remote) {
		if (mc_snprint_cstr_cstr_u64_cstr(path, sizeof(path), "/api/v1/timelines/public?limit=", "", n, "") <= 0) return 1;
	} else {
		if (mc_snprint_cstr_cstr_u64_cstr(path, sizeof(path), "/api/v1/timelines/public?local=true&limit=", "", n, "") <= 0) return 1;
	}

	static char body[262144];
	mc_usize body_len = 0;
	if (masto_http_get_body_via_tls13(argv0, instance, instance, path, body, sizeof(body), &body_len) != 0) {
		print_str("error: fetch failed\n");
		return 1;
	}

	// Expect a top-level array.
	const char *arr = body;
	if (!arr || body_len == 0 || arr[0] != '[') {
		print_str("error: unexpected response\n");
		return 1;
	}

	mc_usize pos = 0;
	for (mc_u64 idx = 0; idx < n; idx++) {
		const char *obj = MC_NULL;
		mc_usize obj_len = 0;
		if (masto_json_next_object_in_array(arr, body_len, &pos, &obj, &obj_len) != 0) break;

		char created_at[64];
		char content_html[4096];
		char content_txt[4096];
		char acct[128];
		char display_name[256];
		mc_u64 reblogs = 0;
		mc_u64 favs = 0;
		mc_u64 replies = 0;
		created_at[0] = 0;
		content_html[0] = 0;
		acct[0] = 0;
		display_name[0] = 0;
		(void)masto_json_get_string_field(obj, obj_len, "created_at", created_at, sizeof(created_at));
		(void)masto_json_get_string_field(obj, obj_len, "content", content_html, sizeof(content_html));
		(void)masto_json_get_u64_field(obj, obj_len, "reblogs_count", &reblogs);
		(void)masto_json_get_u64_field(obj, obj_len, "favourites_count", &favs);
		(void)masto_json_get_u64_field(obj, obj_len, "replies_count", &replies);

		const char *acct_obj = MC_NULL;
		mc_usize acct_obj_len = 0;
		if (masto_json_find_object_field(obj, obj_len, "account", &acct_obj, &acct_obj_len) == 0) {
			(void)masto_json_get_string_field(acct_obj, acct_obj_len, "acct", acct, sizeof(acct));
			(void)masto_json_get_string_field(acct_obj, acct_obj_len, "display_name", display_name, sizeof(display_name));
		}
		masto_html_strip(content_html, mc_strlen(content_html), content_txt, sizeof(content_txt));

		print_str("@");
		print_str(acct[0] ? acct : "?");
		print_str(" · ");
		print_str(created_at[0] ? created_at : "?");
		print_nl();
		if (display_name[0]) {
			print_str(display_name);
			print_nl();
		}
		print_str(content_txt[0] ? content_txt : "");
		print_nl();
		print_str("Boosts: ");
		print_u64(reblogs);
		print_str(" · Favs: ");
		print_u64(favs);
		print_str(" · Replies: ");
		print_u64(replies);
		print_nl();
		print_str("────────────────────────────────────\n");
	}
	return 0;
}

static int cmd_home(const char *argv0, const char *instance, const char *token, int argc, char **argv, int i) {
	// Defaults
	mc_u64 n = 20;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "masto home -n N");
			{
				mc_u64 tmp = 0;
				if (mc_parse_u64_dec(argv[++i], &tmp) != 0) mc_die_usage(argv0, "masto home -n N");
				n = tmp;
			}
			if (n == 0) n = 1;
			if (n > 40) n = 40;
			continue;
		}
		mc_die_usage(argv0, "masto home [-n N]");
	}

	if (!token || !*token) {
		mc_die_usage(argv0, "TOKEN=... masto home");
	}

	char path[256];
	if (mc_snprint_cstr_cstr_u64_cstr(path, sizeof(path), "/api/v1/timelines/home?limit=", "", n, "") <= 0) return 1;

	static char body[262144];
	mc_usize body_len = 0;
	if (masto_http_get_body_via_tls13_bearer_get(argv0, instance, instance, path, token, body, sizeof(body), &body_len) != 0) {
		print_str("error: fetch failed\n");
		return 1;
	}

	if (body_len == 0 || body[0] != '[') {
		print_str("error: unexpected response (expected JSON array)\n");
		if (body_len) {
			mc_usize take = body_len;
			if (take > 1024u) take = 1024u;
			(void)mc_sys_write(1, body, take);
			print_nl();
		}
		return 1;
	}

	mc_usize pos = 0;
	for (mc_u64 idx = 0; idx < n; idx++) {
		const char *obj = MC_NULL;
		mc_usize obj_len = 0;
		if (masto_json_next_object_in_array(body, body_len, &pos, &obj, &obj_len) != 0) break;

		char created_at[64];
		char content_html[4096];
		char content_txt[4096];
		char acct[128];
		char display_name[256];
		mc_u64 reblogs = 0;
		mc_u64 favs = 0;
		mc_u64 replies = 0;
		created_at[0] = 0;
		content_html[0] = 0;
		acct[0] = 0;
		display_name[0] = 0;
		(void)masto_json_get_string_field(obj, obj_len, "created_at", created_at, sizeof(created_at));
		(void)masto_json_get_string_field(obj, obj_len, "content", content_html, sizeof(content_html));
		(void)masto_json_get_u64_field(obj, obj_len, "reblogs_count", &reblogs);
		(void)masto_json_get_u64_field(obj, obj_len, "favourites_count", &favs);
		(void)masto_json_get_u64_field(obj, obj_len, "replies_count", &replies);

		const char *acct_obj = MC_NULL;
		mc_usize acct_obj_len = 0;
		if (masto_json_find_object_field(obj, obj_len, "account", &acct_obj, &acct_obj_len) == 0) {
			(void)masto_json_get_string_field(acct_obj, acct_obj_len, "acct", acct, sizeof(acct));
			(void)masto_json_get_string_field(acct_obj, acct_obj_len, "display_name", display_name, sizeof(display_name));
		}
		masto_html_strip(content_html, mc_strlen(content_html), content_txt, sizeof(content_txt));

		print_str("@");
		print_str(acct[0] ? acct : "?");
		print_str(" · ");
		print_str(created_at[0] ? created_at : "?");
		print_nl();
		if (display_name[0]) {
			print_str(display_name);
			print_nl();
		}
		print_str(content_txt[0] ? content_txt : "");
		print_nl();
		print_str("Boosts: ");
		print_u64(reblogs);
		print_str(" · Favs: ");
		print_u64(favs);
		print_str(" · Replies: ");
		print_u64(replies);
		print_nl();
		print_str("────────────────────────────────────\n");
	}
	return 0;
}

static int cmd_notif(const char *argv0, const char *instance, const char *token, int argc, char **argv, int i) {
	mc_u64 n = 20;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "-n")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "masto notif -n N");
			{
				mc_u64 tmp = 0;
				if (mc_parse_u64_dec(argv[++i], &tmp) != 0) mc_die_usage(argv0, "masto notif -n N");
				n = tmp;
			}
			if (n == 0) n = 1;
			if (n > 40) n = 40;
			continue;
		}
		mc_die_usage(argv0, "masto notif [-n N]");
	}

	if (!token || !*token) mc_die_usage(argv0, "TOKEN=... masto notif");

	char path[256];
	if (mc_snprint_cstr_cstr_u64_cstr(path, sizeof(path), "/api/v1/notifications?limit=", "", n, "") <= 0) return 1;

	static char body[262144];
	mc_usize body_len = 0;
	mc_i32 status = 0;
	if (masto_http_request_body_status_via_tls13(
		argv0,
		instance,
		instance,
		"GET",
		path,
		token,
		MC_NULL,
		MC_NULL,
		0,
		&status,
		body,
		sizeof(body),
		&body_len
	) != 0) {
		print_str("error: fetch failed\n");
		return 1;
	}
	if (status < 200 || status > 299) {
		print_str("error: http ");
		char sbuf[32];
		if (mc_snprint_cstr_i64_cstr(sbuf, sizeof(sbuf), "", (mc_i64)status, "") > 0) print_str(sbuf);
		print_nl();
		if (body_len) {
			mc_usize take = body_len;
			if (take > 1024u) take = 1024u;
			(void)mc_sys_write(1, body, take);
			print_nl();
		}
		return 1;
	}

	if (body_len == 0 || body[0] != '[') {
		print_str("error: unexpected response (expected JSON array)\n");
		if (body_len) {
			mc_usize take = body_len;
			if (take > 1024u) take = 1024u;
			(void)mc_sys_write(1, body, take);
			print_nl();
		}
		return 1;
	}

	mc_usize pos = 0;
	for (mc_u64 idx = 0; idx < n; idx++) {
		const char *obj = MC_NULL;
		mc_usize obj_len = 0;
		if (masto_json_next_object_in_array(body, body_len, &pos, &obj, &obj_len) != 0) break;

		char type[32];
		char created_at[64];
		char acct[128];
		char display_name[256];
		type[0] = 0;
		created_at[0] = 0;
		acct[0] = 0;
		display_name[0] = 0;
		(void)masto_json_get_string_field(obj, obj_len, "type", type, sizeof(type));
		(void)masto_json_get_string_field(obj, obj_len, "created_at", created_at, sizeof(created_at));

		const char *acct_obj = MC_NULL;
		mc_usize acct_obj_len = 0;
		if (masto_json_find_object_field(obj, obj_len, "account", &acct_obj, &acct_obj_len) == 0) {
			(void)masto_json_get_string_field(acct_obj, acct_obj_len, "acct", acct, sizeof(acct));
			(void)masto_json_get_string_field(acct_obj, acct_obj_len, "display_name", display_name, sizeof(display_name));
		}

		print_str(type[0] ? type : "?");
		print_str(" @");
		print_str(acct[0] ? acct : "?");
		print_str(" · ");
		print_str(created_at[0] ? created_at : "?");
		print_nl();
		if (display_name[0]) {
			print_str(display_name);
			print_nl();
		}

		// If present: nested status content (mentions, favourites, reblogs).
		const char *st_obj = MC_NULL;
		mc_usize st_obj_len = 0;
		if (masto_json_find_object_field(obj, obj_len, "status", &st_obj, &st_obj_len) == 0) {
			char content_html[2048];
			char content_txt[2048];
			content_html[0] = 0;
			(void)masto_json_get_string_field(st_obj, st_obj_len, "content", content_html, sizeof(content_html));
			masto_html_strip(content_html, mc_strlen(content_html), content_txt, sizeof(content_txt));
			if (content_txt[0]) {
				print_str(content_txt);
				print_nl();
			}
		}

		print_str("────────────────────────────────────\n");
	}
	return 0;
}

static int cmd_post(const char *argv0, const char *instance, const char *token, int argc, char **argv, int i) {
	// Phase 6: masto post [-u|-p|-d] [-s SPOILER] TEXT...
	if (!token || !*token) mc_die_usage(argv0, "TOKEN=... masto post TEXT");

	const char *visibility = "public";
	const char *spoiler = MC_NULL;

	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "--")) {
			i++;
			break;
		}
		if (mc_streq(a, "-u")) {
			visibility = "unlisted";
			continue;
		}
		if (mc_streq(a, "-p")) {
			visibility = "private";
			continue;
		}
		if (mc_streq(a, "-d")) {
			visibility = "direct";
			continue;
		}
		if (mc_streq(a, "-s")) {
			if (i + 1 >= argc) mc_die_usage(argv0, "masto post -s SPOILER TEXT");
			spoiler = argv[++i];
			continue;
		}
		if (a[0] == '-' && a[1] != 0) {
			mc_die_usage(argv0, "masto post [-u|-p|-d] [-s SPOILER] TEXT");
		}
		break;
	}

	if (i >= argc) mc_die_usage(argv0, "masto post TEXT");

	// Join remaining args as status text (so unquoted multi-word posts work).
	char status_raw[4096];
	status_raw[0] = 0;
	{
		mc_usize o = 0;
		for (int k = i; k < argc; k++) {
			const char *w = argv[k];
			if (!w) continue;
			mc_usize wn = mc_strlen(w);
			if (wn == 0) continue;
			if (o != 0) {
				if (o + 1u >= sizeof(status_raw)) {
					print_str("error: status too long\n");
					return 1;
				}
				status_raw[o++] = ' ';
			}
			if (o + wn >= sizeof(status_raw)) {
				print_str("error: status too long\n");
				return 1;
			}
			mc_memcpy(status_raw + o, w, wn);
			o += wn;
		}
		if (o >= sizeof(status_raw)) {
			print_str("error: status too long\n");
			return 1;
		}
		status_raw[o] = 0;
	}

	char enc_status[4096];
	if (masto_urlencode_form(status_raw, enc_status, sizeof(enc_status)) != 0) {
		print_str("error: status too long\n");
		return 1;
	}

	char enc_spoiler[2048];
	enc_spoiler[0] = 0;
	if (spoiler && *spoiler) {
		if (masto_urlencode_form(spoiler, enc_spoiler, sizeof(enc_spoiler)) != 0) {
			print_str("error: spoiler too long\n");
			return 1;
		}
	}

	char form[8192];
	{
		mc_usize o = 0;
		const char *k0 = "status=";
		mc_usize k0n = mc_strlen(k0);
		mc_usize v0n = mc_strlen(enc_status);
		if (o + k0n + v0n + 1u > sizeof(form)) {
			print_str("error: encode failed\n");
			return 1;
		}
		mc_memcpy(form + o, k0, k0n);
		o += k0n;
		mc_memcpy(form + o, enc_status, v0n);
		o += v0n;

		if (!mc_streq(visibility, "public")) {
			const char *k1 = "&visibility=";
			mc_usize k1n = mc_strlen(k1);
			mc_usize v1n = mc_strlen(visibility);
			if (o + k1n + v1n + 1u > sizeof(form)) {
				print_str("error: encode failed\n");
				return 1;
			}
			mc_memcpy(form + o, k1, k1n);
			o += k1n;
			mc_memcpy(form + o, visibility, v1n);
			o += v1n;
		}

		if (enc_spoiler[0]) {
			const char *k2 = "&spoiler_text=";
			mc_usize k2n = mc_strlen(k2);
			mc_usize v2n = mc_strlen(enc_spoiler);
			if (o + k2n + v2n + 1u > sizeof(form)) {
				print_str("error: encode failed\n");
				return 1;
			}
			mc_memcpy(form + o, k2, k2n);
			o += k2n;
			mc_memcpy(form + o, enc_spoiler, v2n);
			o += v2n;
		}

		form[o] = 0;
	}

	static char body[262144];
	mc_usize body_len = 0;
	mc_i32 status = 0;
	if (masto_http_request_body_status_via_tls13(
		argv0,
		instance,
		instance,
		"POST",
		"/api/v1/statuses",
		token,
		"application/x-www-form-urlencoded",
		form,
		mc_strlen(form),
		&status,
		body,
		sizeof(body),
		&body_len
	) != 0) {
		print_str("error: post failed\n");
		return 1;
	}
	if (status < 200 || status > 299) {
		print_str("error: http ");
		char sbuf[32];
		if (mc_snprint_cstr_i64_cstr(sbuf, sizeof(sbuf), "", (mc_i64)status, "") > 0) print_str(sbuf);
		print_nl();
		if (body_len) {
			mc_usize take = body_len;
			if (take > 1024u) take = 1024u;
			(void)mc_sys_write(1, body, take);
			print_nl();
		}
		return 1;
	}

	// Success returns a Status object; best-effort extract id.
	char id[64];
	id[0] = 0;
	(void)masto_json_get_string_field(body, body_len, "id", id, sizeof(id));
	if (id[0]) {
		print_str("posted: id=");
		print_str(id);
		print_nl();
		return 0;
	}
	// Otherwise print some of the response.
	print_str("posted (unparsed response)\n");
	if (body_len) {
		mc_usize take = body_len;
		if (take > 1024u) take = 1024u;
		(void)mc_sys_write(1, body, take);
		print_nl();
	}
	return 0;
}

int main(int argc, char **argv) {
	const char *argv0 = (argc > 0 && argv[0]) ? argv[0] : "masto";

	const char *instance = MC_NULL;
	const char *token = MC_NULL;

	// Defaults from env.
	token = get_env("TOKEN=");
	instance = get_env("INSTANCE=");

	int i = 1;
	for (; i < argc; i++) {
		const char *a = argv[i];
		if (!a) continue;
		if (mc_streq(a, "-h") || mc_streq(a, "--help")) {
			die_usage(argv0);
		}
		if (mc_streq(a, "-i") || mc_streq(a, "--instance")) {
			if (i + 1 >= argc) die_usage(argv0);
			instance = argv[++i];
			continue;
		}
		if (a[0] == '-' && a[1] != 0) {
			die_usage(argv0);
		}
		break;
	}

	// Default instance (user requested gruene.social) if none is provided.
	if (!instance || !*instance) {
		instance = "gruene.social";
	}

	if (i >= argc) die_usage(argv0);
	const char *cmd = argv[i++];

	// token is used by authenticated endpoints (home/notif/post).

	if (mc_streq(cmd, "ping")) {
		return cmd_ping(argv0, instance);
	}
	if (mc_streq(cmd, "instance")) {
		return cmd_instance(argv0, instance);
	}
	if (mc_streq(cmd, "raw")) {
		if (i >= argc) mc_die_usage(argv0, "masto raw PATH");
		return cmd_raw(argv0, instance, argv[i]);
	}
	if (mc_streq(cmd, "public")) {
		return cmd_public(argv0, instance, argc, argv, i);
	}
	if (mc_streq(cmd, "home")) {
		return cmd_home(argv0, instance, token, argc, argv, i);
	}
	if (mc_streq(cmd, "notif")) {
		return cmd_notif(argv0, instance, token, argc, argv, i);
	}
	if (mc_streq(cmd, "post")) {
		return cmd_post(argv0, instance, token, argc, argv, i);
	}
	if (mc_streq(cmd, "interactive")) {
		return cmd_interactive(argv0, instance, token, argc, argv, i);
	}

	die_usage(argv0);
}
