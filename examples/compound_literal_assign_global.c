struct S {
    long a;
    long b;
    long c;
};

struct S g;

int main() {
    // Seed with non-zero values.
    g.a = 1;
    g.b = 2;
    g.c = 3;

    // In C, (struct S){0} zero-initializes the entire struct.
    g = (struct S){0};
    if (g.a != 0) return 1;
    if (g.b != 0) return 2;
    if (g.c != 0) return 3;

    // Designated initializer should also zero unspecified members.
    g.a = 7;
    g.b = 8;
    g.c = 9;
    g = (struct S){.b = 5};
    if (g.a != 0) return 4;
    if (g.b != 5) return 5;
    if (g.c != 0) return 6;

    return 42;
}
