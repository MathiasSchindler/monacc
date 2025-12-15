// Struct return (SysV sret) + struct-typed conditional lvalue.
// Should compile+run under monacc.

typedef struct {
    long a;
    long b;
    long c;
    long d;
} S;

static S make(long x) {
    S s;
    s.a = x;
    s.b = x + 1;
    s.c = x + 2;
    s.d = x + 3;
    return s;
}

int main(void) {
    S left = make(10);
    S right = make(20);

    // Conditional yields an lvalue (address) selecting between two struct lvalues.
    // Assigning from make(...) exercises: sret call materialization + struct assignment.
    (1 ? left : right) = make(30);

    if (left.a != 30) return 1;
    if (left.d != 33) return 2;
    if (right.a != 20) return 3;

    return 42;
}
