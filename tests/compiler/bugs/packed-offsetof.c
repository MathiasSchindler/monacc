typedef unsigned long size_t;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u64;

struct __attribute__((packed)) P {
  u8 a;   /* offset 0 */
  u64 b;  /* expected offset 1 if packed works */
  u16 c;  /* expected offset 9 */
};

static size_t off_b(void) { return (size_t)&(((struct P *)0)->b); }
static size_t off_c(void) { return (size_t)&(((struct P *)0)->c); }

int main(void) {
  if (off_b() != 1) return 1;
  if (off_c() != 1 + sizeof(u64)) return 2;
  if (sizeof(struct P) != (1 + sizeof(u64) + sizeof(u16))) return 3;
  return 0;
}
