#define MASK 0x1u

int main() {
	int flags = 1;
	if (flags & MASK) return 42;
	return 0;
}
