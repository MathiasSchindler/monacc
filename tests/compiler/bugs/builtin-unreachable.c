int main(void) {
  /* This should compile/link even without a real symbol.
     It must not execute at runtime in this test. */
  if (1) return 0;
  __builtin_unreachable();
}
