struct S {
    char a[1 + 2];
    int b;
};

int main(void) {
    int xs[1 + 2 * 3];
    if ((long long)sizeof(xs) != (long long)(1 + 2 * 3) * (long long)sizeof(int)) return 1;
    if ((long long)sizeof(struct S) != 8LL) return 2;
    return 42;
}
