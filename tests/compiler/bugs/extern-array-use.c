typedef unsigned char u8;

typedef unsigned long size_t;

typedef unsigned long uptr;

extern u8 blob[];

int main(void) {
  /* Ensure it's not resolved to 0 and bytes are correct. */
  if ((uptr)blob == 0) return 1;
  if (blob[0] != 1) return 2;
  if (blob[4] != 5) return 3;
  return 0;
}
