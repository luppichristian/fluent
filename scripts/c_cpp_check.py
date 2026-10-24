#!/usr/bin/env python3
# description: Compile C and C++ source files for fast, portable syntax and warning checks.
"""Run an installed compiler's non-linking syntax check against C/C++ sources."""
from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

EXTENSIONS = {".c": "c", ".cc": "cpp", ".cp": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".c++": "cpp"}
DEFAULTS = {"c": ("CC", ("clang", "gcc", "cc", "cl")), "cpp": ("CXX", ("clang++", "g++", "c++", "cl"))}

def compiler_for(language: str, requested: str | None) -> str | None:
    if requested:
        return shutil.which(requested) or (requested if Path(requested).is_file() else None)
    variable, candidates = DEFAULTS[language]
    if os.environ.get(variable):
        return shutil.which(os.environ[variable])
    return next((shutil.which(name) for name in candidates if shutil.which(name)), None)

def compiler_family(compiler: str) -> str:
    return "msvc" if Path(compiler).name.casefold() in {"cl", "cl.exe"} else "gcc-compatible"

def collect_sources(raw_paths: list[str]) -> tuple[list[tuple[Path, str]], list[str]]:
    found: set[Path] = set()
    ignored: list[str] = []
    for raw in raw_paths:
        path = Path(raw)
        if path.is_file() and path.suffix.casefold() in EXTENSIONS:
            found.add(path)
        elif path.is_dir():
            found.update(item for item in path.rglob("*") if item.is_file() and item.suffix.casefold() in EXTENSIONS)
        else:
            ignored.append(raw)
    return [(path, EXTENSIONS[path.suffix.casefold()]) for path in sorted(found)], ignored

def command(compiler: str, family: str, language: str, standard: str | None, warnings: bool, source: Path) -> list[str]:
    if family == "msvc":
        result = [compiler, "/nologo", "/Zs"]
        if standard and language == "cpp":
            result.append(f"/std:{standard}")
        if warnings:
            result.extend(("/W4", "/WX"))
    else:
        result = [compiler, "-fsyntax-only"]
        if standard:
            result.append(f"-std={standard}")
        if warnings:
            result.extend(("-Wall", "-Wextra", "-Werror"))
    return result + [str(source)]

def run_check(source: Path, language: str, compiler: str, family: str, args: argparse.Namespace) -> dict[str, object]:
    try:
        completed = subprocess.run(command(compiler, family, language, args.standard, args.warnings, source), capture_output=True, text=True, errors="replace", timeout=args.timeout, shell=False)
        diagnostics = (completed.stdout + completed.stderr).strip()
        return {"path": str(source), "language": language, "status": "passed" if completed.returncode == 0 else "failed", "exit_code": completed.returncode, "diagnostics": "" if args.max_diagnostics == 0 else diagnostics[-args.max_diagnostics:]}
    except subprocess.TimeoutExpired:
        return {"path": str(source), "language": language, "status": "timed_out", "exit_code": None, "diagnostics": f"compiler exceeded {args.timeout:g} seconds"}
    except OSError as error:
        return {"path": str(source), "language": language, "status": "unavailable", "exit_code": None, "diagnostics": str(error)}

def main() -> int:
    parser = argparse.ArgumentParser(description="Syntax-check C/C++ source files with an installed compiler; does not link or run code.")
    parser.add_argument("paths", nargs="+", help="C/C++ source files or directories searched recursively")
    parser.add_argument("--language", choices=("auto", "c", "cpp"), default="auto", help="language to check (default: infer from file extension)")
    parser.add_argument("--compiler", help="compiler executable; otherwise use CC/CXX then common compiler names")
    parser.add_argument("--standard", help="language standard, such as c17, c23, c++20, or c++23")
    parser.add_argument("--warnings", action="store_true", help="enable common warnings and treat them as errors")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-source compiler timeout in seconds (default: 30)")
    parser.add_argument("--max-diagnostics", type=int, default=12000, help="maximum diagnostic characters retained per source (default: 12000)")
    parser.add_argument("--json", action="store_true", help="emit a stable machine-readable report")
    args = parser.parse_args()
    if args.timeout <= 0 or args.max_diagnostics < 0:
        parser.error("--timeout must be positive and --max-diagnostics must be non-negative")
    selected, ignored = collect_sources(args.paths)
    if args.language != "auto":
        selected = [(path, language) for path, language in selected if language == args.language]
    compilers: dict[str, object] = {}
    results: list[dict[str, object]] = []
    for language in ("c", "cpp"):
        items = [path for path, item_language in selected if item_language == language]
        if not items:
            continue
        compiler = compiler_for(language, args.compiler)
        if not compiler:
            compilers[language] = {"status": "unavailable", "path": None}
            results.extend({"path": str(path), "language": language, "status": "unavailable", "exit_code": None, "diagnostics": f"no {language} compiler found"} for path in items)
            continue
        family = compiler_family(compiler)
        compilers[language] = {"status": "available", "path": compiler, "family": family}
        results.extend(run_check(path, language, compiler, family, args) for path in items)
    summary = {status: sum(item["status"] == status for item in results) for status in ("passed", "failed", "unavailable", "timed_out")}
    summary["checked"] = len(results)
    summary["status"] = "no_matching_sources" if not results else ("passed" if summary["passed"] == len(results) else "failed")
    report = {"tool": "c_cpp_check", "schema_version": 1, "requested_language": args.language, "standard": args.standard, "warnings_as_errors": args.warnings, "compilers": compilers, "invalid_paths": sorted(set(ignored)), "results": results, "summary": summary}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"c_cpp_check: {summary['status']} ({summary['passed']}/{summary['checked']} passed)")
        for item in results:
            if item["status"] != "passed":
                print(f"{item['status']}: {item['path']}\n{item['diagnostics']}", file=sys.stderr)
    return 0 if summary["status"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
