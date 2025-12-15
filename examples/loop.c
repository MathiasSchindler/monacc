int main() {
    int acc = 0;
    int i = 0;

    for (i = 0; i < 10; i = i + 1) {
        acc = acc + i;
    }

    // sum 0..9 = 45
    if (acc == 45) {
        return 42;
    }
    return 1;
}
