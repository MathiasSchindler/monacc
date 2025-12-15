// Test constant array index optimization
int main() {
    int arr[5];
    arr[0] = 10;
    arr[1] = 11;
    arr[2] = 12;
    arr[3] = 4;
    arr[4] = 5;

    // Test constant indices
    if (arr[0] != 10) return 1;
    if (arr[1] != 11) return 2;
    if (arr[2] != 12) return 3;
    if (arr[3] != 4) return 4;
    if (arr[4] != 5) return 5;

    // Test char array with constant indices
    char buf[4];
    buf[0] = 'A';
    buf[1] = 'B';
    buf[2] = 'C';
    buf[3] = 0;
    if (buf[0] != 'A') return 6;
    if (buf[2] != 'C') return 7;

    // Test pointer with constant index
    int *p = arr;
    if (p[0] != 10) return 8;
    if (p[2] != 12) return 9;
    if (p[4] != 5) return 10;

    // Sum using constant indices
    int sum = arr[0] + arr[1] + arr[2] + arr[3] + arr[4];
    if (sum != 42) return 11;

    return 42;
}
