int duplicate(int x) {
    return x + 1;
}

static int accumulate_a(int *buf, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        total += buf[i];
    }
    return total;
}
