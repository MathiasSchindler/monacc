// Signed 8-bit load must sign-extend when promoted.
int main() {
    char c = -1;
    if (c < 0) return 42;
    return 0;
}
