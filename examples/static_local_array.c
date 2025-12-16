unsigned char *getbuf(void) {
    static unsigned char buf[4096];
    buf[0] = 0x5a;
    return buf;
}

void clobber(void) {
    unsigned char x[8192];
    for (int i = 0; i < (int)sizeof(x); i++) x[i] = 0;
}

int main() {
    unsigned char *p = getbuf();
    clobber();
    if (p[0] != 0x5a) return 1;

    p[0] = 0x33;
    clobber();
    if (p[0] != 0x33) return 2;

    return 42;
}
