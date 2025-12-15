struct S {
    int a[2];
    char b[3];
};

int main() {
    struct S s;
    s.a[0] = 41;
    s.a[1] = 1;
    s.b[0] = 7;
    return s.a[0] + s.a[1];
}
