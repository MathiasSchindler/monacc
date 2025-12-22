int main(void) {
    int i = 0;

    while (1) {
        i = i + 1;
        if (i < 3) {
            continue;
        }
        break;
    }

    if (i == 3) {
        return 42;
    }
    return 1;
}
