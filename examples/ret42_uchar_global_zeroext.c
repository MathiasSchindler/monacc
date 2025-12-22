// Unsigned 8-bit global load must zero-extend when promoted.
unsigned char g = 255;

int main() {
    if (g < 0) return 0;
    return 42;
}
