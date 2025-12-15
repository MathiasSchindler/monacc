int main(void) {
    long long x = 1;
    long long y = 2;

    // Precedence: & > ^ > | > && > ||
    // 1 | (2 ^ 4) = 1 | 6 = 7
    if ( (1 | 2 ^ 4) != 7 ) return 1;

    // (1 & 3) ^ 6 = 1 ^ 6 = 7
    if ( ((1 & 3) ^ 6) != 7 ) return 2;

    x |= 6; // 1 | 6 = 7
    if (x != 7) return 3;

    y ^= 3; // 2 ^ 3 = 1
    if (y != 1) return 4;

    return 42;
}
