# monacc tools tests

This folder contains the shell-based test suite for monacc userland tools.

## Quick start

- Run everything (default, used by `make test`):
  - `sh tests/tools/run.sh`
- Run only smoke tests:
  - `sh tests/tools/run.sh smoke`
- Run only integration tests:
  - `sh tests/tools/run.sh integration`
- Run only real-world tests (aka “recipes”):
  - `sh tests/tools/run.sh realworld`
- Run multiple suites:
  - `sh tests/tools/run.sh smoke integration`

`tests/tools/run.sh --help` prints the supported suite names.

## Suite types

- **smoke**: Fast, direct tool sanity checks (mostly running binaries directly).
- **integration**: Exercises sysbox `sh` + pipes/redirects with sysbox-only PATH.
- **realworld**: Longer “recipes” that look like real user tasks.

## Layout

- `tests/tools/run.sh`
  - Single entrypoint and orchestrator.
  - Sets up a temporary workspace and runs suites.

- `tests/tools/suites/`
  - Canonical suite implementations:
    - `smoke.sh` (aggregator)
    - `smoke.d/` (smoke modules)
    - `integration.sh`
    - `realworld.sh`
    - `require_bins.sh` (verifies required tool binaries exist)

- `tests/tools/lib/testlib.sh`
  - Shared helpers (assertions + “tools-only” runners like `run_box`).

- `tests/tools/data/`
  - Deterministic fixtures used by realworld tests.

## Environment knobs

- `SB_TEST_SUITES="..."`
  - Space-separated list of suites to run.
  - Overrides CLI args.

- `SB_TEST_SHOW_SUITES=1`
  - Include smoke status in the final `OK (...)` line.

- `SB_TEST_DEBUG=1`
  - Print `MARK: ...` breadcrumbs.

- `SB_TEST_VERBOSE=1`
  - Verbose assertions (prints more context on failure in integration/realworld).

- `SB_TEST_NO_REALWORLD=1` / `SB_TEST_NO_RECIPES=1`
  - Skip the realworld/recipes suite.

## Adding tests

### Add a new smoke test

Prefer adding a new block to the most relevant module in `tests/tools/suites/smoke.d/`.
If the module is getting large, create a new numbered module and add it to the
ordered list in `tests/tools/suites/smoke.sh`.

### Add a new integration test

Add it to `tests/tools/suites/integration.sh` using helpers from `tests/tools/lib/testlib.sh`:

- `run_box "..."` to run sysbox `sh -c` with a clean environment and `PATH=$BIN`.
- `assert_eq`, `assert_rc`, etc.

### Add a new real-world recipe

Add scenarios to `tests/tools/suites/realworld.sh`.
Guidelines:

- Use `tests/tools/data/` for input fixtures.
- Prefer pipelines that match supported tool features (see `status.md`).
- Keep results deterministic (avoid depending on wall-clock time or host-specific
  `/proc` contents beyond what’s already covered by smoke).
