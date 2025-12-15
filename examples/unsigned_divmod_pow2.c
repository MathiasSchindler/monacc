// Validates unsigned div/mod by powers of two (codegen peepholes).
// All examples are expected to exit with code 42.

int main(void) {
    unsigned long x = 123;
    if (x / 8 != 15) return 1;
    if (x % 8 != 3) return 2;

    unsigned long y = 0xfffffffffffffff0UL;
    if (y / 16 != 0x0fffffffffffffffUL) return 3;
    if (y % 16 != 0) return 4;

    // Make sure we don't crash on trivial cases.
    unsigned long z = 0;
    if (z / 2 != 0) return 5;
    if (z % 2 != 0) return 6;

    return 42;
}
