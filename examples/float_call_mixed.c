// Verify mixed integer + float argument assignment under SysV ABI.
// Int/pointer args use %rdi..%r9; float args use %xmm0..%xmm7 (separate sequences).

static float mix(int a, float b, int c, float d, int e, float g) {
    float fa;
    float fc;
    float fe;

    fa = (float)a;
    fc = (float)c;
    fe = (float)e;

    // Construct a value with distinct decimal digits when cast to int.
    // With a=1,b=2,c=3,d=4,e=5,g=6 => 654321.
    return fa + (b * 10.0f) + (fc * 100.0f) + (d * 1000.0f) + (fe * 10000.0f) + (g * 100000.0f);
}

int main(void) {
    float r;
    int x;

    r = mix(1, 2.0f, 3, 4.0f, 5, 6.0f);
    x = (int)r;
    if (x != 654321) return 1;

    return 42;
}
