// Exercises: short-circuit && and || as expressions (aarch64-darwin)

int main(void) {
    int g = 0;
    if (0 && (g = 1)) {
        return 0;
    }

    int h = 0;
    if (1 || (h = 1)) {
        // should short-circuit, leaving h == 0
    }

    return 42 + g + h;
}
