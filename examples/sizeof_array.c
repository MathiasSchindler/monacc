int main() {
    // Global array
    static unsigned long gdt[7];

    // Local array
    unsigned long ldt[7];

    // sizeof(array) should be total byte size, not pointer size.
    if ((int)sizeof(gdt) != (int)(7 * (int)sizeof(unsigned long))) return 1;
    if ((int)sizeof(ldt) != (int)(7 * (int)sizeof(unsigned long))) return 2;

    // String literals are arrays; sizeof includes the trailing NUL.
    if ((int)sizeof("abc") != 4) return 3;

    return 42;
}
