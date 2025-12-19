// Verify passing >8 float arguments (forces stack passing after %xmm7).

static float sum10(float a0, float a1, float a2, float a3, float a4,
                   float a5, float a6, float a7, float a8, float a9) {
    // Weighted sum (order matters) to catch mis-assignment.
    return a0 * 2.0f + a1 * 3.0f + a2 * 5.0f + a3 * 7.0f + a4 * 11.0f +
           a5 * 13.0f + a6 * 17.0f + a7 * 19.0f + a8 * 23.0f + a9 * 29.0f;
}

int main(void) {
    float r;
    int x;

    r = sum10(1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f);
    x = (int)r;
    if (x != 952) return 1;

    return 42;
}
