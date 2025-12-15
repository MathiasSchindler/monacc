typedef struct {
    char name[128];
    int x;
} Local;

typedef struct {
    Local locals[512];
    int nlocals;
    int next_offset;
} Locals;

static int add_one(Locals *ls) {
    Local *l = &ls->locals[ls->nlocals++];
    l->x = 123;
    return ls->nlocals;
}

int main(void) {
    Locals ls = {0};
    int r = add_one(&ls);
    if (r != 1) return 1;
    if (ls.nlocals != 1) return 2;
    if (ls.locals[0].x != 123) return 3;
    return 42;
}
