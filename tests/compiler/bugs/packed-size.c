typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long u64;

struct __attribute__((packed)) Q {
  u8 a;
  u64 b;
  u16 c;
};

int main(void) {
  /* Packed layout should remove natural alignment padding. */
  if (sizeof(struct Q) != (1 + (int)sizeof(u64) + (int)sizeof(u16))) return 1;
  return 0;
}
