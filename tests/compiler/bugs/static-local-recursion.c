typedef unsigned char u8;
typedef unsigned long uptr;

static u8 *get_buf_rec(int depth) {
  static u8 buf[32];
  u8 *here = buf;

  if (depth <= 0) {
    buf[0] = 123;
    return here;
  }

  u8 *p = get_buf_rec(depth - 1);

  /* If 'static' storage was incorrectly implemented as stack storage,
     recursion would produce different addresses per frame. */
  if ((uptr)p != (uptr)here) return (u8 *)0;

  return p;
}

int main(void) {
  u8 *p = get_buf_rec(8);
  if (!p) return 1;
  if (p[0] != 123) return 2;
  return 0;
}
