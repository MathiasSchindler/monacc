typedef unsigned long u64;
typedef unsigned char u8;

typedef unsigned long size_t;

struct S {
  u64 a;
  u64 b;
  u64 c;
};

static int all_zero(const u8 *p, size_t n) {
  size_t i = 0;
  while (i < n) {
    if (p[i] != 0) return 0;
    i++;
  }
  return 1;
}

int main(void) {
  struct S s;

  s.a = 1;
  s.b = 2;
  s.c = 3;

  s = (struct S){0};

  if (!all_zero((const u8 *)&s, sizeof(s))) return 1;
  return 0;
}
