// Regression: `extern T name[];` must NOT allocate local BSS storage.
// It must behave as an (incomplete) array type that decays to pointer in expressions.

extern unsigned char blob[];

// Define the symbol in assembly in this same compilation unit.
// If the compiler incorrectly emits a local BSS symbol `blob`, GAS will error on redefinition.
void define_blob(void) {
    __asm__(
        ".section .rodata\n"
        ".globl blob\n"
        "blob:\n"
        "  .byte 1, 2, 3, 0\n"
        ".section .text\n");
}

int main() {
    // Ensure the declaration is treated as array/pointer for indexing.
    if (blob[0] != 1) return 1;
    if (blob[1] != 2) return 2;
    if (blob[2] != 3) return 3;
    return 42;
}
