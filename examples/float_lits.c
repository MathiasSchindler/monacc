// Float literals: decimal point, leading dot, and scientific exponent.
// This is a regression test for lexer -> IEEE-754 binary32 conversion.

int main(void) {
    float a = .5f;       // 0.5
    float b = 15e-1f;    // 1.5
    float c = 5.;        // 5.0 (no suffix)
    float d = 1e2f;      // 100.0
    float e = 125e-3f;   // 0.125

    int x = (int)(a + b + c);      // 0.5 + 1.5 + 5.0 = 7.0
    int y = (int)(d * e);          // 100.0 * 0.125 = 12.5 -> trunc to 12

    if (x == 7 && y == 12) {
        return 42;
    }
    return 0;
}
