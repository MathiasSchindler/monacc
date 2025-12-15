int main() {
    int x = 42;
    int *p = &x;
    if (*p != 42) return 1;
    *p = 7;
    if (x != 7) return 2;
    return 42;
}
