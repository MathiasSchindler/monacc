// Signed 16-bit load must sign-extend when promoted.
int main() {
    short s = -1;
    if (s < 0) return 42;
    return 0;
}
