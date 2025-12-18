int main() {
    int i = -1;

    // Signed comparisons against zero must work.
    if (i >= 0) return 1;
    if (!(i < 0)) return 2;

    // Common pattern: reverse loop down to 0.
    int n = 0;
    int s = 0;
    for (int j = n - 1; j >= 0; j--) {
        s++;
        if (s > 10) return 3; // guard against a missing loop-exit branch
    }

    return 42;
}
