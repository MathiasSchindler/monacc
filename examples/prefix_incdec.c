int main(void) {
    int x = 40;
    int y = ++x;
    if (x != 41) return 1;
    if (y != 41) return 2;

    y = --x;
    if (x != 40) return 3;
    if (y != 40) return 4;

    int a[2];
    a[0] = 41;
    a[1] = 42;
    int *p = a;
    ++p;
    return *p;
}
