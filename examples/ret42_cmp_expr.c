// Exercises: comparisons as value-producing expressions (aarch64-darwin)

int main(void) {
    // (41 < 42) yields 1
    return 41 + (41 < 42);
}
