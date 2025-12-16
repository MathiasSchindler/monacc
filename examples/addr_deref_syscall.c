#include "../core/mc.h"

struct S {
    char c;
    char d;
};

int main(void) {
    char buf[] = "ab";
    char *p = buf;
    int i = 1;

    struct S s;
    s.c = 'X';
    s.d = 'Y';
    struct S *sp = &s;

    mc_i64 r1 = mc_sys_write(1, &*p, 1);
    mc_i64 r2 = mc_sys_write(1, &p[1], 1);
    mc_i64 r3 = mc_sys_write(1, &sp->c, 1);
    mc_i64 r4 = mc_sys_write(1, p + 1, 1);
    mc_i64 r5 = mc_sys_write(1, p + i, 1);
    mc_i64 r6 = mc_sys_write(1, (p + 1) - i, 1);
    mc_i64 r8 = mc_sys_write(1, p + (i + 1), 1);
    mc_i64 r9 = mc_sys_write(1, p + (1 + i), 1);
    mc_i64 r10 = mc_sys_write(1, p + (i - 1), 1);

    int iarr[2];
    iarr[0] = 0;
    iarr[1] = 0;
    int *ip = iarr;
    int j = 1;
    mc_i64 r7 = mc_sys_write(1, ip + j, 1);

    if (r1 == 1 && r2 == 1 && r3 == 1 && r4 == 1 && r5 == 1 && r6 == 1 && r7 == 1 && r8 == 1 && r9 == 1 && r10 == 1) return 42;
    return 1;
}
