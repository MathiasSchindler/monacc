typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

int main(void) {
  u64 x = 0x1122334455667788UL;
  u8 lo8 = 0;
  u16 lo16 = 0;
  u32 lo32 = 0;
  u64 full = 0;

  /* Exercise GNU asm operand modifiers:
     - %bN 8-bit register
     - %wN 16-bit register
     - %kN 32-bit register
     - %qN 64-bit register

     Use plain mov between regs; we only check the observed values.
  */
  __asm__ volatile ("mov %b1, %0" : "=r"(lo8)  : "r"(x));
  __asm__ volatile ("mov %w1, %0" : "=r"(lo16) : "r"(x));
  __asm__ volatile ("mov %k1, %0" : "=r"(lo32) : "r"(x));
  __asm__ volatile ("mov %q1, %0" : "=r"(full) : "r"(x));

  if (lo8 != (u8)x) return 1;
  if (lo16 != (u16)x) return 2;
  if (lo32 != (u32)x) return 3;
  if (full != x) return 4;
  return 0;
}
