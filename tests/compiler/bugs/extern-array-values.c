typedef unsigned char u8;
typedef unsigned long uptr;

extern u8 blob[];

static int check(void) {
  if ((uptr)blob == 0) return 1;
  if (blob[0] != 1) return 2;
  if (blob[1] != 2) return 3;
  if (blob[2] != 3) return 4;
  if (blob[3] != 4) return 5;
  if (blob[4] != 5) return 6;
  return 0;
}

int main(void) {
  return check();
}
