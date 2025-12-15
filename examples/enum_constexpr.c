enum {
    A = 1 << 3,
    B = A + 2,
    C = ~0,
};

int main(void) {
    if (A != 8) return 1;
    if (B != 10) return 2;
    if (C != -1) return 3;
    return 42;
}
