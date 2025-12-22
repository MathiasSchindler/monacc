// Array decay + pointer arithmetic + deref bring-up test.
int a[2] = { 0, 42 };

int main() {
    int *p = a;      // array decays to pointer
    return *(p + 1); // pointer arithmetic scales by sizeof(int)
}
