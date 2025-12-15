struct S {
    int a;
    char b;
};

int main(void) {
    struct S x;
    x = (struct S){ .a = 41, .b = 'x' };
    if (x.a != 41) return 1;
    if (x.b != 'x') return 2;

    struct S y;
    y = (struct S){ .a = 42 };
    if (y.a != 42) return 3;
    if (y.b != 0) return 4;

    return 42;
}
