// bmpview - display BMP image as ASCII art
// Usage: bmpview [FILE]  or  cat image.bmp | bmpview

#include "mc.h"

// BMP headers (packed)
struct bmp_hdr {
mc_u8 magic[2];
mc_u32 file_size;
mc_u32 reserved;
mc_u32 data_offset;
mc_u32 info_size;
mc_i32 width;
mc_i32 height;
mc_u16 planes;
mc_u16 bpp;
mc_u32 compression;
} __attribute__((packed));

static const char RAMP[] = "@%#*+=-:. ";

static int read_exact(mc_i32 fd, void *buf, mc_usize n) {
mc_u8 *p = (mc_u8 *)buf;
while (n > 0) {
mc_i64 r = mc_sys_read(fd, p, n);
if (r <= 0) return -1;
p += r;
n -= (mc_usize)r;
}
return 0;
}

static int skip_bytes(mc_i32 fd, mc_usize n) {
mc_u8 tmp[64];
while (n > 0) {
mc_usize c = n > 64 ? 64 : n;
if (read_exact(fd, tmp, c) < 0) return -1;
n -= c;
}
return 0;
}

static void die(const char *msg) {
mc_write_str(2, "bmpview: ");
mc_write_str(2, msg);
mc_write_str(2, "\n");
mc_exit(1);
}

int main(int argc, char **argv) {
mc_i32 fd = 0;

if (argc > 1) {
if (mc_streq(argv[1], "-h") || mc_streq(argv[1], "--help")) {
mc_write_str(1, "Usage: bmpview [FILE]\nDisplay BMP as ASCII art.\n");
return 0;
}
if (argv[1][0] != '-' || argv[1][1]) {
fd = (mc_i32)mc_sys_openat(MC_AT_FDCWD, argv[1], MC_O_RDONLY, 0);
if (fd < 0) die("open");
}
}

struct bmp_hdr h;
if (read_exact(fd, &h, sizeof(h)) < 0) die("read");
if (h.magic[0] != 'B' || h.magic[1] != 'M') die("not BMP");
if (h.bpp != 24 || h.compression != 0) die("format");

mc_i32 w = h.width, ht = h.height, flip = 1;
if (ht < 0) { ht = -ht; flip = 0; }
if (w <= 0 || ht <= 0 || w > 4096 || ht > 4096) die("size");

mc_usize skip = h.data_offset - sizeof(h);
if (skip > 0 && skip_bytes(fd, skip) < 0) die("seek");

mc_usize row_sz = (mc_usize)w * 3;
mc_usize pad = (4 - (row_sz & 3)) & 3;
mc_usize total = row_sz * (mc_usize)ht;

mc_i64 mem = mc_sys_mmap(0, total, 3, 0x22, -1, 0);
if (mem < 0) die("mmap");
mc_u8 *px = (mc_u8 *)mem;

for (mc_i32 y = 0; y < ht; y++) {
if (read_exact(fd, px + y * row_sz, row_sz) < 0) die("read");
if (pad && skip_bytes(fd, pad) < 0) die("read");
}

char line[4097];
for (mc_i32 y = 0; y < ht; y++) {
mc_u8 *row = px + (flip ? ht - 1 - y : y) * row_sz;
for (mc_i32 x = 0; x < w; x++) {
mc_u32 b = row[x*3], g = row[x*3+1], r = row[x*3+2];
mc_u32 lum = (r*2 + g*3 + b) / 6;
line[x] = RAMP[(lum * 9) / 255];
}
line[w] = '\n';
mc_write_all(1, line, (mc_usize)w + 1);
}

mc_sys_munmap(px, total);
if (fd > 0) mc_sys_close(fd);
return 0;
}
