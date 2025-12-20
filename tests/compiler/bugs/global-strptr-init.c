static const char *USAGE = "Usage: test\n";

int main(void) {
  /* Regression: the compiler/linker must keep pointer-to-string-literal
     global initializers. Historically this was emitted as zero-initialized
     storage, making USAGE NULL at runtime. */
  return (USAGE[0] == 'U') ? 0 : 1;
}
