// Unsigned 8-bit load must zero-extend when promoted.
int main() {
    unsigned char c = 255;
    if (c < 0) return 0;
    return 42;
}
