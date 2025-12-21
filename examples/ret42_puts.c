// Exercises: string literal emission + pointer argument passing (aarch64-darwin)

extern int puts(const char *);

int main(void) {
    puts("monacc darwin\n");
    return 42;
}
