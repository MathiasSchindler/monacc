#include "mc.h"

#define KV_IDX(l,p,i) ((l) * 100 + (p) * 10 + (i))

static void write_str(int fd, const char *s)
{
    int len = 0;
    while (s[len]) len++;
    mc_sys_write(fd, s, len);
}

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

    /* reverse */
    {
        char out[32];
        int j;
        for (j = 0; j < i; j++) {
            out[j] = buf[i - 1 - j];
        }
        mc_sys_write(fd, out, i);
    }
}

static int id_int(int x)
{
    return x;
}

static float id_float(float x)
{
    return x;
}

static int mix_int_float(int a, float b, int c, float d)
{
    /* force use of both int and float args */
    float sum = b + d;
    int isum = a + c;
    return isum + (int)sum;
}

int main(void)
{
    write_str(1, "=== monacc feature probe ===\n");

    /* 1) Float comparisons via C operators (needs ucomiss + jp/jnp support) */
    {
        float a = 1.0f;
        float b = 2.0f;
        int lt = 0;
        int eq = 0;
        if (a < b) lt = 1;
        if (a == a) eq = 1;
        write_str(1, "float cmp (<): ");
        write_int(1, lt);
        write_str(1, "\n");
        write_str(1, "float cmp (==): ");
        write_int(1, eq);
        write_str(1, "\n");
    }

    /* 2) Casts used directly as call arguments */
    {
        int x = id_int((int)3.7f);
        float y = id_float((float)42);
        write_str(1, "cast callarg (int)(3.7f): ");
        write_int(1, x);
        write_str(1, "\n");
        write_str(1, "cast callarg (float)42: ");
        write_int(1, (int)y);
        write_str(1, "\n");

        /* Mixed int/float args (SysV ABI register assignment) */
        write_str(1, "mixed call (1,2.5,3,4.5): ");
        write_int(1, mix_int_float(1, 2.5f, 3, 4.5f));
        write_str(1, "\n");
    }

    /* 3) Multiple declarations on one line */
    {
        int *p, *q;
        int v = 7;
        p = &v;
        q = &v;
        write_str(1, "multi-decl ptrs: ");
        write_int(1, *p + *q);
        write_str(1, "\n");
    }

    /* 4) '*' expressions in array sizes */
    {
        int arr[3 * 4];
        int i;
        int sum = 0;
        for (i = 0; i < 12; i++) {
            arr[i] = i;
            sum += arr[i];
        }
        write_str(1, "array size expr (3*4) sum: ");
        write_int(1, sum);
        write_str(1, "\n");
    }

    /* 5) Multi-argument macro expansion */
    {
        write_str(1, "macro KV_IDX(1,2,3): (disabled; does not expand)\n");
    }

    write_str(1, "=== probe done ===\n");

    mc_exit(0);
    return 0;
}
