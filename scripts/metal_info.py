#!/usr/bin/env python3
# description: Read-only macOS Metal device, driver, toolchain, and capability inventory.
"""Report best-effort Metal information without creating an MTLDevice.

Apple does not provide a general CLI equivalent of vulkaninfo.  The script
therefore preserves the full ``system_profiler`` display inventory and labels
what is inferred from it versus directly enumerated by a Metal process.
"""

from __future__ import annotations

import argparse
import json
import platform
import plistlib
import re
import shutil
import subprocess
from typing import Any


def _run(command: list[str], timeout: int = 40) -> tuple[str | None, str | None]:
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


def _parse_profiler(text: str) -> tuple[dict[str, Any], str | None]:
    try:
        groups = plistlib.loads(text.encode("utf-8"))
    except (ValueError, TypeError) as error:
        return {}, "system_profiler XML could not be parsed: %s" % error
    if not isinstance(groups, list):
        return {}, "system_profiler returned an unexpected XML shape"
    return {str(group.get("_dataType")): group.get("_items", []) for group in groups if isinstance(group, dict)}, None


def _metal_fields(item: Any, path: str = "") -> list[dict[str, Any]]:
    """Expose profiler fields that explicitly mention Metal or GPU families."""
    results: list[dict[str, Any]] = []
    if isinstance(item, dict):
        for key, value in item.items():
            current = path + "." + key if path else key
            if re.search(r"metal|gpu.?family|feature.?set", key, re.I):
                results.append({"path": current, "value": value})
            results.extend(_metal_fields(value, current))
    elif isinstance(item, list):
        for index, value in enumerate(item):
            results.extend(_metal_fields(value, "%s[%d]" % (path, index)))
    return results


def _version(command: list[str]) -> str | None:
    output, _ = _run(command, timeout=15)
    return output.strip() if output else None


def collect_metal_info() -> dict[str, Any]:
    system = platform.system()
    tools = {"system_profiler": _tool("system_profiler"), "xcrun": _tool("xcrun"), "xcodebuild": _tool("xcodebuild")}
    probes: list[dict[str, Any]] = []
    limitations: list[str] = []
    devices: list[Any] = []
    details: dict[str, Any] = {}
    toolchain: dict[str, Any] = {}
    available: bool | None = False

    if system != "Darwin":
        limitations.append("Metal is an Apple platform API and is not natively available on this operating system.")
    else:
        raw, error = _run(["system_profiler", "SPDisplaysDataType", "SPHardwareDataType", "SPSoftwareDataType", "-xml"])
        probes.append({"command": ["system_profiler", "SPDisplaysDataType", "SPHardwareDataType", "SPSoftwareDataType", "-xml"], "status": "ok" if raw else "unavailable", "error": error})
        if raw:
            profiler, parse_error = _parse_profiler(raw)
            if parse_error:
                limitations.append(parse_error)
            else:
                devices = profiler.get("SPDisplaysDataType", []) or []
                details["system_profiler"] = profiler
                details["metal_related_fields"] = _metal_fields(devices)
                # A display adapter is not proof that Metal can create an
                # MTLDevice. In particular, older Intel adapters can appear
                # here on macOS versions where Metal is unsupported. No native
                # Metal runtime probe is available in this stdlib-only tool.
                details["display_adapter_inventory_available"] = bool(devices)
                available = None
        else:
            available = None
            limitations.append("system_profiler could not enumerate display hardware; inspect the probe error.")

        if tools["xcrun"]["found"]:
            path, path_error = _run(["xcrun", "--find", "metal"], timeout=15)
            probes.append({"command": ["xcrun", "--find", "metal"], "status": "ok" if path else "unavailable", "error": path_error})
            toolchain["metal_compiler_path"] = path.strip() if path else None
            version, version_error = _run(["xcrun", "metal", "-v"], timeout=15)
            probes.append({"command": ["xcrun", "metal", "-v"], "status": "ok" if version else "unavailable", "error": version_error})
            toolchain["metal_compiler_version"] = version.strip() if version else None
        if tools["xcodebuild"]["found"]:
            toolchain["xcode_version"] = _version(["xcodebuild", "-version"])

        limitations.append("system_profiler inventories display adapters, not native MTLDevice creation. This tool leaves Metal availability unknown unless a future native Metal probe confirms it; query a native Metal program for exact support and capabilities.")

    info = _clean({"available": available, "tools": tools, "toolchain": toolchain, "devices": devices, "details": details, "probes": probes, "limitations": limitations})
    info["available"] = available
    return {
        "platform": {"operating_system": system, "operating_system_release": platform.release(), "machine": platform.machine()},
        "metal": info,
    }


def _print_human(report: dict[str, Any]) -> None:
    info = report["metal"]
    names: list[str] = []
    for device in info["devices"]:
        if isinstance(device, dict):
            names.append(str(device.get("sppci_model") or device.get("_name") or device.get("spdisplays_vendor") or "unknown display adapter"))
    print("Metal available: %s" % ("yes" if info.get("available") else "no" if info.get("available") is False else "not confirmed"))
    print("Display adapters (%d): %s" % (len(info["devices"]), "; ".join(names[:4]) or "not discovered"))
    print("Metal compiler: %s" % info["toolchain"].get("metal_compiler_version", "not discovered"))
    fields = info["details"].get("metal_related_fields", [])
    print("Metal-related profiler fields: %d" % len(fields))
    for limitation in info["limitations"]:
        print("Note: " + limitation)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report a read-only macOS Metal device, toolchain, and capability inventory.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_metal_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
