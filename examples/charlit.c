int main() {
    if ('A' != 65) return 1;
    if ('\n' != 10) return 2;
    if ('\x2a' != 42) return 3;
    return 42;
}
