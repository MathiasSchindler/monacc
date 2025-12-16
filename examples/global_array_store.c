unsigned char buf[16];

int main() {
    buf[3] = 0x42;
    if (buf[3] != 0x42) return 1;
    buf[15] = 0x7f;
    if (buf[15] != 0x7f) return 2;
    return 42;
}
