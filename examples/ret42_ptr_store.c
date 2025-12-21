// Exercises: store through pointer (aarch64-darwin)

int main(void) {
    int x = 0;
    int *p = &x;
    *p = 42;
    return x;
}
