static int f(void) {
    static char s[] = "abc";
    if (sizeof(s) != 4) return 1;
    if (s[0] == 'a') s[0] = 'z';
    return s[0];
}

int main() {
    int a = f();
    int b = f();
    if (a != 'z') return 2;
    if (b != 'z') return 3;
    return 42;
}
