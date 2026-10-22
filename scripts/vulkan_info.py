#!/usr/bin/env python3
# description: Read-only Vulkan loader, instance, device, layer, extension, and capability inspector.
"""Report the Vulkan view exposed by the installed Vulkan SDK/runtime.

``vulkaninfo --json`` is the authoritative optional probe.  Its schema changes
between SDK releases, so the unmodified decoded document is retained under
``details`` instead of discarding driver-specific features or formats.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


def _run(command: list[str], timeout: int = 60) -> tuple[str | None, str | None]:
    if not shutil.which(command[0]):
        return None, "not installed or not on PATH"
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=timeout), None
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
        import os
        path = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "vulkan-1.dll"
        return [str(path)] if path.is_file() else []
    if system == "Darwin":
        return []  # Vulkan needs a portability implementation such as MoltenVK.
    candidates = [Path("/usr/lib/libvulkan.so.1"), Path("/usr/lib64/libvulkan.so.1"), Path("/lib/x86_64-linux-gnu/libvulkan.so.1")]
    return [str(path) for path in candidates if path.exists()]


def _find_values(value: Any, names: set[str], results: list[dict[str, Any]], path: str = "") -> None:
    """Extract useful cross-SDK fields while retaining the complete document."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = (path + "." if path else "") + key
            if key.lower() in names:
                results.append({"path": child, "value": item})
            _find_values(item, names, results, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _find_values(item, names, results, "%s[%d]" % (path, index))


def _summary(document: Any) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    _find_values(document, {"devicename", "apiversion", "driverversion", "drivername", "driverversion", "vendorid", "deviceid", "devicetype", "layername", "extensionname", "queuename", "queuetype"}, found)
    # Deduplicate exact occurrences caused by aliases in older vulkaninfo output.
    compact: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in found:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            compact.append(item)
    return {"selected_fields": compact}


def _parse_text_summary(text: str) -> dict[str, Any]:
    """Preserve and lightly structure vulkaninfo's cross-version summary."""
    devices: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        gpu = re.match(r"^GPU(\d+):\s*$", line)
        if gpu:
            current = {"index": gpu.group(1)}
            devices.append(current)
            continue
        pair = re.match(r"^\s*([A-Za-z][A-Za-z0-9]+)\s*=\s*(.*)$", line)
        if current is not None and pair:
            current[pair.group(1)] = pair.group(2).strip()
    extensions = sorted(set(re.findall(r"\bVK_[A-Za-z0-9_]+\b", text)))
    instance = re.search(r"Vulkan Instance Version:\s*([^\s]+)", text)
    return {
        "instance_version": instance.group(1) if instance else None,
        "instance_extensions_and_layer_names": extensions,
        "devices": devices,
        "raw": text[:500_000],
    }


def _parse_json(text: str) -> tuple[Any | None, str | None]:
    try:
        return json.loads(text), None
    except json.JSONDecodeError as error:
        return None, "vulkaninfo returned non-JSON output: %s" % error.msg


def _vulkaninfo_json() -> tuple[Any | None, str | None]:
    """Read a Vulkan Profiles JSON report without letting the tool write here.

    Some Vulkan SDK versions print JSON to stdout, while current Windows
    builds create ``VP_VULKANINFO_*.json`` in their working directory.  A
    private temporary directory supports both forms and is deleted on return.
    """
    executable = shutil.which("vulkaninfo")
    if not executable:
        return None, "not installed or not on PATH"
    try:
        with tempfile.TemporaryDirectory(prefix="vulkan-info-") as directory:
            result = subprocess.run(
                [executable, "--json"], cwd=directory, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False,
            )
            reports = list(Path(directory).glob("VP_VULKANINFO_*.json"))
            if reports:
                try:
                    return json.loads(reports[0].read_text(encoding="utf-8")), None
                except (OSError, json.JSONDecodeError) as error:
                    return None, "generated Vulkan Profiles JSON could not be read: %s" % error
            if result.stdout.strip():
                document, error = _parse_json(result.stdout)
                if document is not None:
                    return document, None
                return None, error
            diagnostic = result.stderr.strip() or "vulkaninfo did not emit a JSON report"
            return None, diagnostic
    except subprocess.TimeoutExpired:
        return None, "timed out"
    except OSError as error:
        return None, str(error)


def collect_vulkan_info() -> dict[str, Any]:
    tools = {"vulkaninfo": _tool("vulkaninfo")}
    probes: list[dict[str, Any]] = []
    limitations: list[str] = []
    details: Any = {}
    summary: dict[str, Any] = {"selected_fields": []}
    available: bool | None = None

    if tools["vulkaninfo"]["found"]:
        text_summary, summary_error = _run(["vulkaninfo", "--summary"])
        probes.append({"command": ["vulkaninfo", "--summary"], "status": "ok" if text_summary else "unavailable", "error": summary_error})
        if text_summary:
            summary["runtime"] = _parse_text_summary(text_summary)
        # --json is intentionally used instead of parsing the pretty human
        # output, and includes layers, formats, queues, features, and limits
        # when the local SDK exposes them.
        details, error = _vulkaninfo_json()
        probes.append({"command": ["vulkaninfo", "--json"], "status": "ok" if details is not None else "unavailable", "error": error})
        if details is not None:
            json_summary = _summary(details)
            summary["selected_fields"] = json_summary["selected_fields"]
            available = True
        else:
            available = None
            limitations.append("vulkaninfo could not enumerate a Vulkan instance or physical device; inspect the probe error.")
    else:
        limitations.append("vulkaninfo is absent, so loader presence cannot prove that a Vulkan instance/device is usable.")

    loaders = _loader_paths()
    if loaders:
        limitations.append("A Vulkan loader was found, but it is not proof of an installed ICD or usable physical device.")
    if platform.system() == "Darwin":
        limitations.append("macOS does not expose native Vulkan; a portability implementation such as MoltenVK must be installed for Vulkan tooling to report devices.")
    info = _clean({"available": available, "tools": tools, "loader_paths": loaders, "summary": summary, "details": details, "probes": probes, "limitations": limitations})
    # A failed or warning-only probe is distinct from a proven unavailable API.
    info["available"] = available
    return {
        "platform": {"operating_system": platform.system(), "operating_system_release": platform.release(), "machine": platform.machine()},
        "vulkan": info,
    }


def _print_human(report: dict[str, Any]) -> None:
    info = report["vulkan"]
    summary = info["summary"]["selected_fields"]
    runtime = info["summary"].get("runtime", {})
    devices = [item["value"] for item in summary if item["path"].lower().endswith("devicename")]
    devices = devices or [item.get("deviceName", "unknown") for item in runtime.get("devices", [])]
    extensions = [item["value"] for item in summary if item["path"].lower().endswith("extensionname")]
    extensions = extensions or runtime.get("instance_extensions_and_layer_names", [])
    print("Vulkan available: %s" % ("yes" if info.get("available") else "no" if info.get("available") is False else "unknown"))
    print("Devices (%d): %s" % (len(devices), "; ".join(str(value) for value in devices[:4]) or "not discovered"))
    print("Reported extensions: %d; selected fields: %d" % (len(extensions), len(summary)))
    for limitation in info["limitations"]:
        print("Note: " + limitation)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report a read-only Vulkan loader, device, layer, extension, and capability inventory.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_vulkan_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
