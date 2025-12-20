# monacc app development quick reference (LLM distro)

Date: 2025-12-20

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

Do not call libc APIs like `printf`, `malloc`, `strcpy`, `getaddrinfo`, etc.

---

## 3) Writing a new app/tool

Place source at `tools/<name>.c` and build output at `bin/<name>`.

Common tool shape:

- Parse args early; on misuse call `mc_die_usage(argv0, "...")` (exits 2).
- On syscall failure call `mc_die_errno(argv0, "context", rc)`.
- Write output using `mc_write_*` helpers.
- Keep memory bounded: fixed-size buffers and explicit caps.

---

## 4) How to compile with monacc (copy/paste recipes)

The compiler binary is `bin/monacc`.

Important ordering rule:

- monacc emits `_start` **only for the first input file**. Therefore the *first* `.c` file should be your tool (e.g. `tools/foo.c`).

### 4.1 “Default” build (simple, works for most tools)

From the repo root:

`./bin/monacc -I core tools/foo.c \
  core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_libc_compat.c core/mc_start_env.c core/mc_io.c core/mc_regex.c \
  core/mc_sha256.c core/mc_hmac.c core/mc_hkdf.c core/mc_aes.c core/mc_gcm.c core/mc_x25519.c \
  core/mc_tls_record.c core/mc_tls13.c core/mc_tls13_transcript.c core/mc_tls13_handshake.c \
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

## 8) If you are blocked: write a request spec (don’t patch core/compiler)

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
