int main() {
    if ("hi"[0] != 'h') return 1;
    if ("hi"[1] != 'i') return 2;
    char *p = "hi";
    p = p + 1;
    if (*p != 'i') return 3;
    return 42;
}
