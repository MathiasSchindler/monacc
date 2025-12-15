typedef int myint;

typedef struct {
    int a;
} S;

int main() {
    myint x = 41;
    S s;
    s.a = 1;
    return x + s.a;
}
