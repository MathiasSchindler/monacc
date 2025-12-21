// Unsigned 16-bit load must zero-extend when promoted.
int main() {
    unsigned short s = 65535;
    if (s < 0) return 0;
    return 42;
}
