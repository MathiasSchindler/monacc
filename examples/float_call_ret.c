// Verify SysV float calling convention: pass/return float in XMM regs.

static float add_scale(float a, float b) {
    return (a + b) * 2.0f;
}

int main(void) {
    float r;
    int x;

    r = add_scale(1.5f, 2.0f);
    x = (int)(r * 10.0f);
    if (x != 70) return 1;

    return 42;
}
