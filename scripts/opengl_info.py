#!/usr/bin/env python3
# description: Read-only OpenGL runtime, extension, capability, and framebuffer configuration inspector.
"""Inspect the OpenGL implementation visible to the current session.

No context is created by this script.  On Unix-like systems ``glxinfo`` is the
optional, authoritative context probe; without it, the presence of a loader is
not treated as proof that a usable OpenGL renderer is available.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _run(command: list[str], timeout: int = 25) -> tuple[str | None, str | None]:
    if not shutil.which(command[0]):
        return None, "not installed or not on PATH"
    try:
        output = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=timeout)
        return output, None
    except subprocess.TimeoutExpired:
        return None, "timed out"
    except (OSError, subprocess.CalledProcessError) as error:
        return None, str(error)


def _tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return {"found": bool(path), "path": path}


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items() if item not in (None, "")}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


def _loader_paths() -> list[str]:
    system = platform.system()
    if system == "Windows":
        root = Path(str(__import__("os").environ.get("SystemRoot", r"C:\\Windows"))) / "System32" / "opengl32.dll"
        return [str(root)] if root.is_file() else []
    if system == "Darwin":
        framework = Path("/System/Library/Frameworks/OpenGL.framework/OpenGL")
        return [str(framework)] if framework.exists() else []
    candidates = [Path("/usr/lib/libGL.so.1"), Path("/usr/lib64/libGL.so.1")]
    return [str(path) for path in candidates if path.exists()]


def _parse_glxinfo(text: str) -> dict[str, Any]:
    runtime: dict[str, Any] = {}
    capability_values: dict[str, str] = {}
    extensions: set[str] = set()
    configurations: list[dict[str, str]] = []
    current_section = ""
    wrapped_extension_lines = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        match = re.match(r"^(server|client|OpenGL core profile|OpenGL compatibility profile|OpenGL ES profile) (?:glx )?(vendor string|version string|extensions):\s*(.*)$", stripped, re.I)
        if match:
            group, label, value = match.groups()
            key = "%s_%s" % (re.sub(r"\W+", "_", group.lower()).strip("_"), re.sub(r"\W+", "_", label.lower()).strip("_"))
            if label.lower() == "extensions":
                extensions.update(re.findall(r"\b(?:GLX|GL|EGL)_[A-Za-z0-9_]+", value))
                wrapped_extension_lines = True
            else:
                runtime[key] = value or None
                wrapped_extension_lines = False
            continue
        match = re.match(r"^(OpenGL vendor string|OpenGL renderer string|OpenGL version string|OpenGL shading language version string):\s*(.*)$", stripped)
        if match:
            runtime[match.group(1).lower().replace(" ", "_")] = match.group(2) or None
            wrapped_extension_lines = False
            continue
        if stripped.lower().endswith("extensions:"):
            current_section = stripped[:-1]
            wrapped_extension_lines = True
            continue
        if "fbconfig" in stripped.lower():
            current_section = stripped
        if wrapped_extension_lines and re.match(r"^(?:GLX|GL|EGL)_[A-Za-z0-9_]", stripped):
            extensions.update(re.findall(r"\b(?:GLX|GL|EGL)_[A-Za-z0-9_]+", stripped))
            continue
        wrapped_extension_lines = False
        match = re.match(r"^\s*(GL_[A-Z0-9_]+)\s*=\s*(.+)$", line)
        if match:
            capability_values[match.group(1)] = match.group(2).strip()
            continue
        # glxinfo -l prints FBConfig records as a whitespace table. Preserve
        # the non-ambiguous raw rows instead of guessing column meanings.
        if current_section.lower().startswith("fbconfig") and stripped and re.match(r"^0x[0-9a-f]+", stripped, re.I):
            configurations.append({"source": "glxinfo FBConfig", "raw": stripped})

    return {
        "runtime": _clean(runtime),
        "extensions": sorted(extensions),
        "capabilities": capability_values,
        "configurations": configurations,
    }


def collect_opengl_info() -> dict[str, Any]:
    system = platform.system()
    tools = {"glxinfo": _tool("glxinfo"), "eglinfo": _tool("eglinfo")}
    probes: list[dict[str, Any]] = []
    details: dict[str, Any] = {"runtime": {}, "extensions": [], "capabilities": {}, "configurations": []}
    limitations: list[str] = []
    available: bool | None = None

    if tools["glxinfo"]["found"]:
        output, error = _run(["glxinfo", "-l"])
        probes.append({"command": ["glxinfo", "-l"], "status": "ok" if output is not None else "unavailable", "error": error})
        if output:
            details = _parse_glxinfo(output)
            available = bool(details["runtime"].get("opengl_renderer_string"))
            if not available:
                limitations.append("glxinfo ran but did not expose an OpenGL renderer; the display server or context may be unavailable.")
        else:
            limitations.append("glxinfo could not create or query a GLX context; inspect the probe error and display-session configuration.")
    else:
        limitations.append("glxinfo is absent, so this script cannot safely enumerate a live OpenGL context.")

    if tools["eglinfo"]["found"]:
        output, error = _run(["eglinfo"])
        probes.append({"command": ["eglinfo"], "status": "ok" if output is not None else "unavailable", "error": error})
        if output:
            details["egl_summary"] = output[:200_000]

    loaders = _loader_paths()
    if loaders:
        details["loader_paths"] = loaders
    if system in {"Windows", "Darwin"}:
        limitations.append("This platform has no bundled context enumerator in the standard library. A loader/framework can exist without a usable hardware context.")
    info = _clean({"available": available, "tools": tools, **details, "probes": probes, "limitations": limitations})
    # Availability is deliberately tri-state, so preserve an unknown value.
    info["available"] = available
    return {
        "platform": {"operating_system": system, "operating_system_release": platform.release(), "machine": platform.machine()},
        "opengl": info,
    }


def _print_human(report: dict[str, Any]) -> None:
    info = report["opengl"]
    runtime = info["runtime"]
    print("OpenGL available: %s" % ("yes" if info.get("available") else "no" if info.get("available") is False else "unknown"))
    print("Renderer: %s" % runtime.get("opengl_renderer_string", "not discovered"))
    print("Version: %s" % runtime.get("opengl_version_string", "not discovered"))
    print("Extensions: %d; capabilities: %d; framebuffer configurations: %d" % (len(info["extensions"]), len(info["capabilities"]), len(info["configurations"])))
    for limitation in info["limitations"]:
        print("Note: " + limitation)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report a read-only OpenGL runtime, extensions, capabilities, and configurations.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_opengl_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
