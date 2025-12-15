struct S {
    char a;
    int b;
};

int main() {
    struct S s;
    s.a = 1;
    s.b = 41;
    return s.a + s.b;
}
