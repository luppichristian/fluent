#!/usr/bin/env python3
# description: Generate JUMP.md from described fluent resources.
"""Generate the fluent resource index."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RESOURCE_DIRS = ("rules", "scripts", "subagents", "tasks")
IGNORED_NAMES = {"__pycache__", ".DS_Store"}
DESCRIPTION = re.compile(r"^\s*(?:(?:#|//|;|::)\s*|REM\s+)?description\s*:\s*(.+?)\s*$", re.IGNORECASE)


def files_in(directory: Path) -> list[Path]:
    return sorted(
        (path for path in directory.rglob("*") if path.is_file() and not any(part in IGNORED_NAMES for part in path.parts)),
        key=lambda path: path.as_posix().lower(),
    )


def description(path: Path) -> str | None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:32]:
        match = DESCRIPTION.match(line)
        if match:
            return match.group(1).strip().strip("'\"") or None
    return None


def render() -> tuple[str, list[Path]]:
    missing: list[Path] = []
    lines = [
        "# fluent resource index", "",
        "<!-- Maintained manually; verified by .github/workflows/gen_jump_file.py. -->", "",
    ]
    for name in RESOURCE_DIRS:
        directory = ROOT / name
        lines.extend((f"## {name}", ""))
        entries = files_in(directory) if directory.is_dir() else []
        lines.extend(entry(path, missing) for path in entries) if entries else lines.append("- No files yet.")
        lines.append("")
    return "\n".join(lines), missing


def entry(path: Path, missing: list[Path]) -> str:
    relative = path.relative_to(ROOT).as_posix()
    text = description(path)
    if text is None:
        missing.append(path)
        text = "**Missing description metadata.**"
    return f"- [{relative}]({relative}): {text}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate JUMP.md from fluent resources.")
    parser.add_argument("--check", action="store_true", help="fail if JUMP.md is stale or metadata is missing")
    args = parser.parse_args()
    output, missing = render()
    target = ROOT / "JUMP.md"
    current = target.read_text(encoding="utf-8") if target.exists() else ""
    if current != output:
        if args.check:
            print("JUMP.md is stale; run .github/workflows/gen_jump_file.py")
            return 1
        target.write_text(output, encoding="utf-8", newline="\n")
    if missing:
        print("Missing description metadata: " + ", ".join(path.relative_to(ROOT).as_posix() for path in missing))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
