# monacc app development quick reference (LLM distro)

Date: 2025-12-21

This file is the single “reference sheet” for an LLM working in a *minimal monacc distro*.
That distro contains only:

- `bin/` (compiler + built tools)
- `core/` (the reusable `mc_*` runtime/library)
- `tools/` (source of tools/apps)

Policy: the LLM should **not** add tests or change build/test infrastructure. If something is missing or broken in `core/` or the compiler, do **not** “fix it”; write a short request spec (see §8).

---

## 1) Hard constraints

- Target: **Linux x86-64 only** (SysV ABI).
- Output: **syscall-only**, **no glibc/libc** dependency.
- Binaries should be **static** and standalone (no shared libraries).
- Prefer small and robust over feature-complete.

Exit codes (tool convention):

- `0` success
- `1` operational error (I/O, parse, network)
- `2` usage error (bad CLI)

---

## 2) Where the “stdlib” is

Use the in-tree `mc_*` APIs from `core/`.

Typical includes in a tool:

- `#include "mc.h"`
- Optionally `#include "mc_net.h"` (networking)
- Optionally TLS/crypto headers (`mc_tls13.h`, `mc_sha256.h`, etc.)
- Optionally `#include "mc_tls13_client.h"` (TLS 1.3 client over an existing fd)

Do not call libc APIs like `printf`, `malloc`, `strcpy`, `getaddrinfo`, etc.

---

## 3) Writing a new app/tool

Place source at `tools/<name>.c` and build output at `bin/<name>`.

Tool identity and layout (project convention):

1) Each tool has a canonical name (lowercase, no spaces), e.g. `browse`.
2) The main tool source file is `tools/<name>.c`, e.g. `tools/browse.c`.
3) Each tool has a directory `tools/<name>/`.
4) That directory contains:
  - `tools/<name>/<name>-info.md` (short doc: purpose, usage, build recipe, notes)
  - any additional `.c/.h` sources or data files needed to build the tool

Source layout convention:

- Exactly one top-level file per tool: `tools/<name>.c`
- All other `.c`/`.h` and resources for that tool go under: `tools/<name>/...`

Include convention:

- In `tools/<name>.c`, include helper headers via subpath, e.g. `#include "<name>/<name>_json.h"`.
- In helper `.c` files under `tools/<name>/`, include sibling headers normally (e.g. `#include "<name>_json.h"`).

Common tool shape:

- Parse args early; on misuse call `mc_die_usage(argv0, "...")` (exits 2).
- On syscall failure call `mc_die_errno(argv0, "context", rc)`.
- Write output using `mc_write_*` helpers.
- Keep memory bounded: fixed-size buffers and explicit caps.

---

## 4) How to compile with monacc (copy/paste recipes)

The compiler binary is `bin/monacc`.

Notes from recent bring-up work:

- `monacc` is not `gcc`/`clang`: it does **not** accept common warning/optimization flags like `-Wall`, `-Wextra`, `-O2`.
  - Keep build commands to `monacc`'s supported flags (`-I`, `-D`, `-o`, etc.).
  - If you need to compare behavior with a “normal” toolchain, use `--as as --ld ld` (see §4.2).
- Avoid linking `core/mc_start.c` into tools built with `monacc`.
  - `core/mc_start.c` defines `_start`; including it can cause `duplicate global symbol _start` at link time.
  - For env access, prefer reading `/proc/self/environ` (tool-side) or link `core/mc_start_env.c` if you rely on `mc_get_start_envp()`.

Important ordering rule:

- monacc emits `_start` **only for the first input file**. Therefore the *first* `.c` file should be your tool (e.g. `tools/foo.c`).

### 4.1 “Default” build (simple, works for most tools)

From the repo root:

`./bin/monacc -I core tools/foo.c tools/foo/foo_util.c \
  core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c core/mc_start_env.c core/mc_io.c core/mc_regex.c \
  core/mc_sha256.c core/mc_hmac.c core/mc_hkdf.c core/mc_aes.c core/mc_gcm.c core/mc_x25519.c \
    core/mc_tls_record.c core/mc_tls13.c core/mc_tls13_transcript.c core/mc_tls13_handshake.c core/mc_tls13_client.c \
  core/mc_mathf.c \
  -o bin/foo`

Notes:

- That list is the “common core set” typically linked into tools.
- If your tool doesn’t use crypto/TLS/math, you *may* omit those `.c` files mainly to reduce compile time and avoid accidental dependencies.
  - In general, monacc emits per-function/per-string sections and links with a `--gc-sections`-equivalent, so **truly unreferenced** code usually does not end up in the final static binary.
  - Caveat: if you reference a symbol in a module, you may pull in more of that module’s reachable code/data.

### 4.2 Forcing external assembler/linker (debug/bring-up)

If you suspect the internal object emitter or linker is the source of a problem:

- external assembler: add `--as as`
- external linker: add `--ld ld`

Example:

`./bin/monacc --as as --ld ld -I core tools/foo.c ... -o bin/foo`

Debug tip:

- If you see a parse error at a line number far beyond the source file length, it may refer to the *preprocessed* output.
  Use `--dump-pp /tmp/foo.pp` to inspect what `monacc` is actually compiling.

### 4.3 Sanity-check that the output is truly standalone

- `file bin/foo` should say “statically linked”.
- `ldd bin/foo` should say “not a dynamic executable”.

---

## 5) Syscall-only mindset

Prefer:

- stack buffers
- small structs
- explicit limits (max line length, max URL length, max items)

Expect to use syscalls via `mc_sys_*` wrappers (open/read/write/poll/socket/connect/getrandom/etc.).

---

## 6) Networking notes (if you do networking)

- Networking code in this ecosystem is **IPv6-first** (often AAAA-only name resolution).
- Use connect timeouts via non-blocking connect + `poll`, then restore blocking for normal I/O.
- Real-world HTTP headers can be large; keep parsing robust against long lines.

---

## 7) Security notes

- TLS/crypto primitives exist in `core/`.
- Unless the tool explicitly implements it, assume **no certificate validation**.
- If you add “secure-looking” features, document limitations in the tool `--help`.

---

## 8) Binary size optimization

Small binaries are a project goal. Here's how to minimize size:

### 8.1 Link only what you need

Start with a minimal set and add modules only as needed:

**Minimal build (most tools):**
```
./bin/monacc -I core tools/foo.c core/mc_str.c core/mc_io.c -o bin/foo
```

**Add modules incrementally:**
- `core/mc_regex.c` — if you use `mc_regex_match_first()`
- `core/mc_fmt.c` + `core/mc_snprint.c` — if you need formatted output helpers

**Avoid `core/mc_libc_compat.c`** — this module provides libc-compatible wrappers (`memcpy`, `strlen`, etc.) and should not be linked. Use the `mc_*` equivalents directly (`mc_memcpy`, `mc_strlen`, etc.).

**Avoid linking unused modules.** While monacc has `--gc-sections`-equivalent dead code elimination, referencing any symbol in a module may pull in related code.

### 8.2 Code-level optimizations

| Technique | Example | Savings |
|-----------|---------|---------|
| Short error messages | `die("read")` vs `die("failed to read BMP header")` | ~20B each |
| Single `die()` function | Consolidate repeated `mc_write_str(2,...); mc_exit(1);` | ~50B+ |
| Merge related structs | Combine file header + info header into one read | ~100B |
| Inline string literals | `mc_write_str(1, "msg")` vs global `static const char *MSG` | minor |
| Smaller temp buffers | `tmp[64]` vs `tmp[256]` for skip loops | minor |
| Reduce max limits | `4096` vs `16384` for max dimensions | reduces stack, minor code |
| Use `mc_sys_*` directly | Avoid wrapper functions for simple syscalls | minor |

### 8.3 Argument parsing pattern (compact)

```c
int main(int argc, char **argv) {
    mc_i32 fd = 0;
    if (argc > 1) {
        if (mc_streq(argv[1], "-h") || mc_streq(argv[1], "--help")) {
            mc_write_str(1, "Usage: tool [FILE]\n");
            return 0;
        }
        if (argv[1][0] != '-' || argv[1][1]) {
            fd = (mc_i32)mc_sys_openat(MC_AT_FDCWD, argv[1], MC_O_RDONLY, 0);
            if (fd < 0) die("open");
        }
    }
    // ... tool logic using fd (0 = stdin) ...
}
```

### 8.4 Compact error handling

```c
static void die(const char *msg) {
    mc_write_str(2, "toolname: ");
    mc_write_str(2, msg);
    mc_write_str(2, "\n");
    mc_exit(1);
}
```

Use short messages: `die("read")`, `die("format")`, `die("size")`.

### 8.5 Size verification

After building, verify size is reasonable:
```
ls -l bin/foo          # should be 3-6 KB for simple tools
file bin/foo           # should say "statically linked"
```

---

## 9) If you are blocked: write a request spec (don't patch core/compiler)

If you suspect a missing `core/` feature or a compiler bug/limitation:

1) Do **not** modify `core/` or `bin/monacc`.
2) Create a request document under `tools/requests/` (create the directory if needed):
   - `tools/requests/<short-topic>.md`

Template:

- **Title**: one line
- **Problem**: what you tried to build, and what failed
- **Expected**: what should happen
- **Observed**: exact error/output (or minimal reproduction)
- **Environment**: Linux x86-64, syscall-only, static, monacc version string if available
- **Proposed API/behavior** (optional): what `core/` function or compiler behavior would fix it

Keep it short and actionable.

Known issue (documented, do not patch core here):

- `core/mc_vsnprintf.c` may fail to compile under `monacc` with a preprocessor error like `#endif without #if`.
  Workaround: use `core/mc_snprint.c` + `core/mc_fmt.c` helpers instead; if you need `mc_vsnprintf`, file a request spec under `tools/requests/`.
