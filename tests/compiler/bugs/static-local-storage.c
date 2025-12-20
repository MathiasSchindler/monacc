typedef unsigned long size_t;

typedef unsigned char u8;

typedef unsigned long uptr;

static u8 *get_buf(void) {
  static u8 buf[32];
  buf[0] = 123;
  return buf;
}

int main(void) {
  u8 *p1 = get_buf();
  u8 *p2 = get_buf();

  if ((uptr)p1 != (uptr)p2) return 1;
  if (p2[0] != 123) return 2;

  return 0;
}
