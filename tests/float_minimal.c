/* Minimal float test for monacc */
#include "mc.h"

static void write_int(int fd, mc_i64 val)
{
    char buf[32];
    int i = 0;
    int neg = 0;
    
    if (val < 0) {
        neg = 1;
        val = -val;
    }
    
    if (val == 0) {
        buf[i++] = '0';
    } else {
        while (val > 0) {
            buf[i++] = '0' + (val % 10);
            val /= 10;
        }
    }
    
    if (neg) buf[i++] = '-';
    
    /* Reverse */
    char out[32];
    int j;
    for (j = 0; j < i; j++) {
        out[j] = buf[i - 1 - j];
    }
    mc_sys_write(fd, out, i);
}

static void write_str(int fd, const char *s)
{
    int len = 0;
    while (s[len]) len++;
    mc_sys_write(fd, s, len);
}

/* Print float as integer * 10000 (no sign handling to avoid comparisons) */
static void write_float_x10000(int fd, float f)
{
    mc_u32 bits;
    {
        const mc_u8 *s = (const mc_u8 *)&f;
        mc_u8 *d = (mc_u8 *)&bits;
        d[0] = s[0];
        d[1] = s[1];
        d[2] = s[2];
        d[3] = s[3];
    }
    mc_i64 val;
    
    /* Check sign bit */
    if (bits & 0x80000000) {
        write_str(fd, "-");
        f = -f;
    }
    
    val = (mc_i64)(f * 10000.0f + 0.5f);
    write_int(fd, val);
}

static void test(const char *name, float val)
{
    write_str(1, name);
    write_str(1, ": ");
    write_float_x10000(1, val);
    write_str(1, "\n");
}

int main(void)
{
    float a;
    float b;
    float c;
    
    write_str(1, "=== Float Tests ===\n");
    
    /* Basic add */
    a = 1.0f;
    b = 2.0f;
    c = a + b;
    test("1.0 + 2.0", c);
    
    /* Subtract */
    a = 5.5f;
    b = 3.2f;
    c = a - b;
    test("5.5 - 3.2", c);
    
    /* Multiply */
    a = 2.5f;
    b = 4.0f;
    c = a * b;
    test("2.5 * 4.0", c);
    
    /* Divide */
    a = 10.0f;
    b = 4.0f;
    c = a / b;
    test("10.0 / 4.0", c);
    
    /* Negative */
    a = -3.0f;
    b = 4.0f;
    c = a * b;
    test("-3.0 * 4.0", c);
    
    /* Small */
    a = 0.1f;
    b = 0.1f;
    c = a * b;
    test("0.1 * 0.1", c);
    
    /* Accumulation */
    {
        float sum = 0.0f;
        int i;
        for (i = 0; i < 10; i++) {
            sum = sum + 0.1f;
        }
        test("sum 10x0.1", sum);
    }
    
    /* Int to float */
    {
        int x = 42;
        c = (float)x;
        test("(float)42", c);
    }
    
    /* Float to int */
    {
        float x = 3.7f;
        int y = (int)x;
        write_str(1, "(int)3.7: ");
        write_int(1, y);
        write_str(1, "\n");
    }
    
    /* Array */
    {
        float arr[4];
        arr[0] = 1.5f;
        arr[1] = 2.5f;
        arr[2] = 3.5f;
        arr[3] = 4.5f;
        c = arr[0] + arr[1] + arr[2] + arr[3];
        test("sum array", c);
    }
    
    /* Dot product */
    {
        float a[4];
        float b[4];
        float dot = 0.0f;
        int i;
        a[0] = 1.0f; a[1] = 2.0f; a[2] = 3.0f; a[3] = 4.0f;
        b[0] = 0.5f; b[1] = 0.5f; b[2] = 0.5f; b[3] = 0.5f;
        for (i = 0; i < 4; i++) {
            dot = dot + a[i] * b[i];
        }
        test("dot product", dot);
    }
    
    write_str(1, "=== Done ===\n");
    
    mc_exit(0);
    return 0;
}
