---
description: Compile C and C++ source files for fast, portable syntax and warning checks.
---

# C/C++ source checker

Runs an installed C or C++ compiler in a non-linking mode against source files. Use it as a quick portable preflight when a full project build is unavailable or too slow: it proves that the chosen compiler can parse the source with the requested language standard and optional warnings-as-errors policy.

## What it checks

- Finds C (`.c`) and C++ (`.cc`, `.cp`, `.cpp`, `.cxx`, `.c++`) sources supplied directly or under a directory.
- Chooses `CC`/`CXX` when set, then common Clang, GCC, or MSVC compiler names; `--compiler` overrides discovery.
- Uses syntax-only checking: no executable is linked, run, installed, or written into the project.
- Reports each file as `passed`, `failed`, `unavailable`, or `timed_out`, with bounded compiler diagnostics.

## Run

```sh
python scripts/c_cpp_check.py src --language c --standard c17 --warnings
python scripts/c_cpp_check.py main.cpp engine --standard c++20 --json
python scripts/c_cpp_check.py source --compiler clang++ --timeout 10
```

## Options

| Option | Default | Effect |
| --- | --- | --- |
| `paths` | required | Source files or directories searched recursively. |
| `--language auto\|c\|cpp` | `auto` | Infer extensions, or check only one language. |
| `--compiler PATH` | auto | Explicit compiler executable. |
| `--standard NAME` | compiler default | Pass a language-standard switch where supported. |
| `--warnings` | off | Enable common warnings and make them errors. |
| `--timeout SECONDS` | `30` | Per-source compiler timeout. |
| `--max-diagnostics N` | `12000` | Bound saved diagnostic text for each source. |
| `--json` | off | Emit the full stable report. |

## Output

`--json` prints a `c_cpp_check` schema-versioned report with selected compilers, invalid inputs, per-file outcomes, diagnostics, and totals. The command exits zero only when at least one source was checked and every check passed.

## Notes

This is intentionally not a build-system substitute. It does not discover project include paths, macros, generated headers, libraries, linker settings, tests, formatting rules, or runtime behavior. Supply the project’s normal build command for those checks. An MSVC result may be `unavailable` outside a Developer Command Prompt because its environment setup is required. MSVC has no equivalent C-language standard switch, so `--standard` is passed to MSVC only for C++.
