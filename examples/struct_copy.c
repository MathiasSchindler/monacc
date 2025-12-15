struct S {
	long a;
	long b;
};

int main() {
	struct S x;
	x.a = 40;
	x.b = 2;

	// Struct initialization by copy.
	struct S y = x;

	// Struct assignment by copy.
	x = y;

	return (int)(x.a + x.b);
}
