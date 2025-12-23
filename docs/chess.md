# Monacc Chess Implementation Plan

**Date:** 2025-12-21
**Target:** Linux x86-64 (monacc distro)

This document outlines the roadmap for building `chess`, a standalone chess engine, and two options for a user interface.

---

## Phase 1: The Core Engine (`tools/chess`)

This component is responsible for game rules, move generation, and "thinking" (Neural Network). It communicates via standard input/output using the **UCI (Universal Chess Interface)** protocol.

### Step 1.1: Data Structures & State
**File:** `tools/chess/chess.h`

* **Board Representation:** Use an "0x88" array representation (size 128) or a simple 64-element array of integers. This simplifies boundary checking without complex bitboards.
* **Structs:**
    ```c
    typedef struct { uint8_t squares[128]; int side; ... } Board;
    typedef struct { uint8_t from; uint8_t to; ... } Move;
    ```
* **Memory:** No `malloc`. All board states and move lists must use stack-allocated fixed-size buffers (e.g., `Move moves[256]`).

### Step 1.2: Move Generation (Component A)
**File:** `tools/chess/movegen.c`

1.  **Pseudo-Legal Generator:** Iterate over the board. For each piece, generate valid sliding/stepping moves.
2.  **Legality Filter:**
    * Function: `int is_square_attacked(Board *b, int sq, int by_side)`
    * Before adding a move to the final list, apply it to a temporary `Board` on the stack.
    * If the King is in check after the move, discard it.

### Step 1.3: Neural Network Evaluation (Component B)
**Files:** `tools/chess/nn.c`, `tools/chess/weights.h`

1.  **Training (External):** Train a small MLP (e.g., 768 -> 64 -> 1) in Python using PyTorch/TensorFlow.
2.  **Export:** Convert trained weights into C arrays in `weights.h`:
    ```c
    static const float L1_WEIGHTS[] = { ... };
    static const float L1_BIAS[] = { ... };
    ```
3.  **Inference:**
    * Link `core/mc_mathf.c` for floating-point math.
    * Implement a simple forward pass function `float eval(Board *b)`.
    * **Optimization:** Use incremental updates if possible, or just re-compute the forward pass (the network is small enough).

### Step 1.4: The UCI Loop
**File:** `tools/chess.c`

* Implement `main()` to read `stdin` line-by-line using `mc_read`.
* Parse standard commands: `uci`, `isready`, `position startpos moves ...`, `go`.
* On `go`:
    1.  Start a search (Alpha-Beta pruning) with a fixed depth or time limit.
    2.  Use `eval(Board *b)` at leaf nodes.
    3.  Print `bestmove <move>` to `stdout`.

---

## Phase 2: User Interface Options

Choose **Option A** for simplicity (one binary) or **Option B** for modularity (recommended for clean architecture).

### Option A: Integrated "Play Mode"

The engine detects a flag (e.g., `--play`) and switches from UCI mode to an interactive TUI (Text User Interface).

**Implementation Steps:**

1.  **Argument Parsing:** Check `argv[1]` in `tools/chess.c`. If `--play`, call `interactive_mode()`.
2.  **Rendering:**
    * Use ANSI escape codes to clear the screen (`\033[2J`) and position the cursor.
    * Print the board using ASCII `+---+` or Unicode characters (♖, ♘).
3.  **Input Loop:**
    * Read user input (e.g., "e2e4").
    * Parse string to `Move` struct.
    * Validate against `gen_legal_moves`.
    * Apply move, then call the search function to get the computer's reply.
4.  **No syscall overhead:** Direct function calls between UI and Engine logic.

### Option B: Separate "Monacc-Chess UI" Project

Create a completely separate tool `tools/chess-ui` that acts as a frontend wrapper around the `bin/chess` engine.

**Files:** `tools/chess-ui.c`, `tools/chess-ui/render.c`

**Implementation Steps:**

1.  **Process Creation:**
    * Use `mc_sys_pipe2` to create two pipes (Parent->Child, Child->Parent).
    * Use `mc_sys_fork` to spawn a child process.
    * In the child:
        * Use `mc_sys_dup2` to bind pipes to stdin/stdout (fd 0 and 1).
        * Use `mc_sys_execve` to launch `bin/chess`.
2.  **Protocol Translator:**
    * **Input:** User types "e4".
    * **Logic:** `chess-ui` maintains its own board state to validate the move visually.
    * **Output:** `chess-ui` sends `position startpos moves ...` and `go` to the engine via the pipe.
3.  **Asynchronous Reading:**
    * Use `mc_sys_poll` to check for engine output ("bestmove ...") without blocking the user input.
4.  **Visuals:**
    * Similar ANSI rendering as Option A, but isolated from the "thinking" logic.

---

## 3. Build Instructions

### Building the Engine (Required for both options)
```bash
./bin/monacc -I core tools/chess.c tools/chess/movegen.c tools/chess/nn.c \
  core/mc_str.c core/mc_fmt.c core/mc_snprint.c core/mc_io.c core/mc_mathf.c \
  -o bin/chess
