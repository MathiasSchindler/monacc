// Test inline assembly support
// Tests the basic patterns used in the kernel

static inline void outb(unsigned short port, unsigned char val) {
    __asm__ volatile ("outb %0, %1" :: "a"(val), "Nd"(port));
}

static inline unsigned char inb(unsigned short port) {
    unsigned char ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

// Test a simple asm with no operands
static inline void cli(void) {
    __asm__ volatile ("cli");
}

static inline void sti(void) {
    __asm__ volatile ("sti");
}

// Test asm with just clobbers
static inline void memory_barrier(void) {
    __asm__ volatile ("" ::: "memory");
}

// Test reading CR2 (page fault address)
static inline unsigned long read_cr2(void) {
    unsigned long val;
    __asm__ volatile ("mov %%cr2, %0" : "=r"(val));
    return val;
}

// Test hlt instruction
static inline void hlt(void) {
    __asm__ volatile ("hlt");
}

// Simple write using inline asm syscall
static inline long my_write(int fd, const char *buf, unsigned long len) {
    long ret;
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(1), "D"(fd), "S"(buf), "d"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}

// Exit using inline asm
static inline void my_exit(int code) {
    __asm__ volatile (
        "syscall"
        :: "a"(60), "D"(code)
        : "rcx", "r11", "memory"
    );
}

int main(void) {
    // Test that inline asm syscalls work
    my_write(1, "OK\n", 3);
    return 0;
}
