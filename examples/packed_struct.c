struct __attribute__((packed)) P {
    char a;
    int b;
    char c;
};

int main() {
    struct P p;
    long off_b = (long)((char *)&p.b - (char *)&p);
    long off_c = (long)((char *)&p.c - (char *)&p);

    // Packed layout: a@0, b@1, c@5; total size 6.
    if ((int)sizeof(struct P) != 6) return 1;
    if (off_b != 1) return 2;
    if (off_c != 5) return 3;

    return 42;
}
