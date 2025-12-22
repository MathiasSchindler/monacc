// Regression test for aarch64-darwin: ensure calls with >6 scalar args
// correctly pass stack arguments.

static int sum9(int a, int b, int c, int d, int e, int f, int g, int h, int i) {
    return a + b + c + d + e + f + g + h + i;
}

int main(void) {
    // 1+2+3+4+5+6+7+8+6 = 42
    return sum9(1, 2, 3, 4, 5, 6, 7, 8, 6);
}
