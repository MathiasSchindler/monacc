// Exercises: unary ! and ~ (aarch64-darwin)

int main(void) {
    // !0 == 1
    int a = 41 + (!0);
    // (~0) & 42 == 42
    int b = (~0) & 42;
    if ((a == 42) && (b == 42)) {
        return 42;
    }
    return 0;
}
