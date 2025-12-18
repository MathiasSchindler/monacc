int main() {
    float a = (float)3;
    float b = (float)4;

    int ok = 1;
    ok &= (a < b);
    ok &= (b > a);
    ok &= (a <= a);
    ok &= (b >= a);
    ok &= (a != b);
    ok &= (a == a);

    return ok ? 42 : 1;
}
