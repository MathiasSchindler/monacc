struct S {
    void (*fp)(int);
    int x;
};

int main() {
    struct S s;
    s.x = 42;
    return s.x;
}
