// Exercises: address-of local + pointer local + deref load (aarch64-darwin)

int main(void) {
    int x = 42;
    int *p = &x;
    return *p;
}
