static unsigned int g = 3;

int main(void) {
    __asm__ volatile(
        "testl $1, g(%rip)\n"
        "jmp .Lskip_data\n"
        ".long 0x11223344\n"
        ".word 0x5566\n"
        ".Lskip_data:\n"
        :
        :
        : "cc"
    );
    return ((g & 1u) == 1u) ? 0 : 1;
}
