int duplicate(int x) {
    return x + 1;
}

static int accumulate_b(int *buf, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += buf[i];
    }
    return sum;
}
