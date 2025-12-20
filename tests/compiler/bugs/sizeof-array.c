typedef unsigned long size_t;

typedef unsigned long u64;

int main(void) {
  u64 a[7];
  (void)a;

  size_t sa = sizeof(a);
  size_t se = sizeof(u64);

  if (sa != 7 * se) return 1;
  if (sizeof(&a[0]) != sizeof(u64 *)) return 2;

  return 0;
}
