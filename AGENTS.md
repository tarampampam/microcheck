# AGENTS - Project Rules

> Read this file AND the global rules before making any code changes -
> https://tarampampam.github.io/.github/ai/AGENTS.md (mirror -
> <https://raw.githubusercontent.com/tarampampam/.github/refs/heads/master/ai/AGENTS.md>).

## Instruction Priority

1. This file (`AGENTS.md` in this repository)
2. Global rules (external URLs)
3. Other documentation

If rules conflict, follow the highest priority source.

## Build & Test Commands

Requires `musl-gcc`, `make`, `cmake`, `python3`. Compile sources on any changes to ensure no warnings or errors.
Run all tests after batching changes to ensure no regressions.

```bash
make       # build all binaries → build/bin/{httpcheck,httpscheck,portcheck,parallel,pidcheck}
make test  # build + run all unit tests (C) + all feature tests (Python)
make fmt   # format all C source with clang-format
make clean # remove build/ and apps/version.h
APP_VERSION=1.2.3 make  # set version string (generates apps/version.h)
```

**Run a single unit test binary**:

```bash
make build/bin/cli_test && ./build/bin/cli_test         # CLI module unit tests
make build/bin/http_test && ./build/bin/http_test       # HTTP module unit tests
make build/bin/command_test && ./build/bin/command_test # command parsing unit tests
```

**Run a single feature test suite**:

```bash
python3 ./tests/feature/httpcheck.py --bin ./build/bin/httpcheck             # HTTP mode
python3 ./tests/feature/httpcheck.py --bin ./build/bin/httpscheck --https    # HTTPS mode (needs openssl)
python3 ./tests/feature/httpcheck.py --bin ./build/bin/httpscheck --fallback # fallback mode (HTTPS->HTTP)
python3 ./tests/feature/portcheck.py --bin ./build/bin/portcheck
python3 ./tests/feature/parallel.py  --bin ./build/bin/parallel
python3 ./tests/feature/pidcheck.py  --bin ./build/bin/pidcheck
```

## Architecture

### Single-source dual-binary pattern

`apps/httpcheck.c` compiles to both `httpcheck` and `httpscheck`. The difference: `httpscheck` is compiled with
`-DWITH_TLS` and linked against mbedTLS 4. All TLS code paths in the file are gated on `#ifdef WITH_TLS`. Both
binaries share the same CLI flags.

### Library modules

- **`lib/cli/`** - CLI argument parsing. Flags have immutable metadata (`cli_flag_meta_t`) and mutable state
  (`cli_flag_state_t`). Three value types: `FLAG_TYPE_BOOL`, `FLAG_TYPE_STRING`, `FLAG_TYPE_STRINGS`. Value
  priority: CLI flag > environment variable > default. Every flag can have a companion `--flag-env` flag to override
  the env var name at runtime.
- **`lib/http/`** - HTTP protocol (no I/O). URL parsing is zero-copy: `host` and `path` fields point into the original
  string, not allocated copies. Use `_len` fields for bounds. `http_build_request()` constructs the full HTTP/1.1
  request string.
- **`lib/command/`** - Parses shell-like quoted command strings into `argv` arrays. Used only by `parallel`.
- **`lib/mbedtls4/`** - Vendored via `lib/install-mbedtls4.sh`, built with cmake. Only linked into `httpscheck`.

### httpscheck auto-detect mode

When the URL has no scheme (`host:port/path` without `http://` or `https://`), `httpscheck` tries HTTPS first,
then falls back to HTTP on any connection/TLS error. The `--connect-timeout` flag controls both the TCP `poll()`
timeout and the `SO_RCVTIMEO` during TLS handshake; after a successful handshake, `SO_RCVTIMEO` is reset to the
full `--timeout`.

### Output discipline

**Do not use `fprintf`, `snprintf`, or other `<stdio.h>` formatting functions in apps**. This bloats binary size.
Use `write()` with string literals or `fputs()` for error output. See the comment at the top of `apps/httpcheck.c`.

### Adding a new flag to an app

Follow the existing pattern in `apps/httpcheck.c`:

1. Define `#define FLAG_*_LONG "flag-name"` and error string constants
2. Define `static const cli_flag_meta_t FLAG_META` and `FLAG_ENV_META` structs
3. `cli_app_add_flag(app, &FLAG_META)` and `..._ENV_META` in `main()`
4. Add both to the NULL-check and `flag_pairs[]` (for env-override wiring)
5. Parse and validate the value using a `parse_*()` function following the style of `parse_timeout()`

### Adding numeric parsing

The project uses manual integer/float parsers (no `strtof`/`atof`) for size and consistency. See `parse_timeout()`
and `parse_connect_timeout()` in `apps/httpcheck.c` for the pattern.

## Feature Test Structure

`tests/feature/httpcheck.py` tests run in three modes selected by flags:

- Default (no flag): HTTP server, tests without `https_only=True` or `fallback_only=True`
- `--https`: HTTPS server, tests with `https_only=True`
- `--fallback`: HTTP server + `httpscheck` binary, tests with `fallback_only=True`

Each `TestCase` replaces `{PORT}` and `{PROTOCOL}` placeholders in `give_args` and `give_env` values at runtime.
