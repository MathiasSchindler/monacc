typedef int *PInt, **PPInt;

// Function-pointer typedef: we treat it as "pointer-sized" and skip the parameter list.
typedef void (*Fn)(int);

struct S {
    Fn f;
    int x;
};

int main() {
    int v = 42;
    PInt p = &v;
    PPInt pp = &p;

    if (**pp != 42) return 1;

    struct S s;
    s.x = 41;
    s.x = s.x + 1;
    return s.x;
}
