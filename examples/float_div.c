int main() {
    float a = (float)7;
    float b = (float)2;
    float c = a / b;
    int x = (int)c;
    // C truncates toward zero: 7/2 = 3.5 -> 3
    return (x == 3) ? 42 : 1;
}
