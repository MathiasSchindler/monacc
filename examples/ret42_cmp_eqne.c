// Exercises: == and != as value-producing expressions (aarch64-darwin)

int main(void) {
    int a = 41;
    int b = 41;
    int c = 42;

    // (a==b) => 1, (b!=c) => 1
    return 40 + (a == b) + (b != c);
}
