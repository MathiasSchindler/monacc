#include "../core/mc.h"

int main(void) {
    mc_sys_write(1, "Hello via inline asm\n", 21);
    return 42;
}
