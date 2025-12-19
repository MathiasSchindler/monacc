static int id_int(int x) { return x; }
static float id_float(float x) { return x; }

static int call_int(int (*fn)(int), int x) { return fn(x); }
static float call_float(float (*fn)(float), float x) { return fn(x); }

int main() {
    int ok = 1;

    // float -> int cast used directly as call argument
    float f = 3.7f;
    int direct = id_int((int)f);
    int tmp = (int)f;
    int via_tmp = id_int(tmp);
    ok &= (direct == via_tmp);

    int (*pfi)(int) = id_int;
    int direct_fp = pfi((int)f);
    int via_tmp_fp = pfi(tmp);
    ok &= (direct_fp == via_tmp_fp);

    int direct_wrap = call_int(id_int, (int)f);
    int via_tmp_wrap = call_int(id_int, tmp);
    ok &= (direct_wrap == via_tmp_wrap);

    int direct_wrap_fp = call_int(pfi, (int)f);
    int via_tmp_wrap_fp = call_int(pfi, tmp);
    ok &= (direct_wrap_fp == via_tmp_wrap_fp);

    // int -> float cast used directly as call argument
    float a = id_float((float)42);
    float t = (float)42;
    float b = id_float(t);
    ok &= ((int)a == 42);
    ok &= ((int)b == 42);
    ok &= ((int)a == (int)b);

    float (*pff)(float) = id_float;
    float c = pff((float)42);
    float d = pff(t);
    ok &= ((int)c == 42);
    ok &= ((int)d == 42);

    float e = call_float(id_float, (float)42);
    float g = call_float(id_float, t);
    ok &= ((int)e == 42);
    ok &= ((int)g == 42);

    float h = call_float(pff, (float)42);
    float i = call_float(pff, t);
    ok &= ((int)h == 42);
    ok &= ((int)i == 42);

    return ok ? 42 : 1;
}
