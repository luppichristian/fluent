#!/usr/bin/env python3
# description: Windows Direct3D, display-adapter, driver, and DxDiag inspector.
"""Report Direct3D information that Windows exposes without third-party modules.

The script deliberately does not infer feature levels or API support from a GPU
name.  Direct3D feature levels are reported only when DxDiag exposes them.
On non-Windows hosts the stable report says that Direct3D is unsupported.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _compact(item) for key, item in value.items() if item not in (None, "")}
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


def _run_powershell(script: str) -> Any:
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        return None
    try:
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", script],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=True,
        )
        return json.loads(completed.stdout) if completed.stdout.strip() else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []


def _windows_inventory() -> tuple[dict[str, Any], str]:
    # CIM documents installed display-driver configuration.  It cannot prove
    # which Direct3D feature levels a driver accepts, so DxDiag is separate.
    script = r'''$ErrorActionPreference='Stop'
$o=[ordered]@{}
$o.adapters=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,AdapterDACType,AdapterRAM,CurrentBitsPerPixel,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,CurrentScanMode,CurrentVideoMode,DriverDate,DriverVersion,InfFilename,InstalledDisplayDrivers,MaxRefreshRate,MinRefreshRate,PNPDeviceID,Status,VideoArchitecture,VideoMemoryType,VideoModeDescription,VideoProcessor)
$o.os=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture
$o.directx=@{}
$keys=@('HKLM:\SOFTWARE\Microsoft\DirectX','HKLM:\SOFTWARE\WOW6432Node\Microsoft\DirectX')
foreach($key in $keys) { if(Test-Path $key) { $p=Get-ItemProperty -Path $key; $o.directx[$key]=[ordered]@{Version=$p.Version;InstalledVersion=$p.InstalledVersion} } }
$o | ConvertTo-Json -Depth 5 -Compress'''
    value = _run_powershell(script)
    return (value, "powershell_cim_and_directx_registry") if isinstance(value, dict) else ({}, "unavailable")


def _normalize_adapter(item: dict[str, Any]) -> dict[str, Any]:
    return _compact({
        "name": item.get("Name"), "vendor": item.get("AdapterCompatibility"),
        "video_processor": item.get("VideoProcessor"), "dac": item.get("AdapterDACType"),
        "dedicated_memory_bytes": item.get("AdapterRAM"), "memory_type": item.get("VideoMemoryType"),
        "architecture": item.get("VideoArchitecture"), "driver_version": item.get("DriverVersion"),
        "driver_date": item.get("DriverDate"), "driver_inf": item.get("InfFilename"),
        "installed_driver_files": item.get("InstalledDisplayDrivers"), "pnp_device_id": item.get("PNPDeviceID"),
        "status": item.get("Status"), "current_mode": {
            "description": item.get("VideoModeDescription") or item.get("CurrentVideoMode"),
            "width": item.get("CurrentHorizontalResolution"), "height": item.get("CurrentVerticalResolution"),
            "bits_per_pixel": item.get("CurrentBitsPerPixel"), "refresh_rate_hz": item.get("CurrentRefreshRate"),
            "scan_mode": item.get("CurrentScanMode"),
        },
        "advertised_refresh_range_hz": {"minimum": item.get("MinRefreshRate"), "maximum": item.get("MaxRefreshRate")},
    })


def _dxdiag_text() -> tuple[str | None, str | None]:
    """Ask the Windows diagnostics tool for a temporary text report.

    DxDiag has no stdout report mode.  Its output is written in a temporary
    file and always removed; this is the only probe that writes anything.
    """
    executable = shutil.which("dxdiag")
    if not executable:
        return None, "dxdiag_not_found"
    handle = tempfile.NamedTemporaryFile(prefix="direct3d_info_", suffix=".txt", delete=False)
    output = handle.name
    handle.close()
    try:
        completed = subprocess.run([executable, "/whql:off", "/t", output], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=50)
        if completed.returncode != 0 or not Path(output).exists():
            return None, "dxdiag_failed"
        return Path(output).read_text(encoding="utf-8", errors="replace"), "dxdiag_text_report"
    except (OSError, subprocess.TimeoutExpired):
        return None, "dxdiag_failed_or_timed_out"
    finally:
        try:
            Path(output).unlink(missing_ok=True)
        except OSError:
            pass


_DXDIAG_FIELD = re.compile(r"^\s*([^:]{1,80}):\s*(.*?)\s*$")


def _parse_dxdiag(text: str) -> dict[str, Any]:
    """Keep DxDiag key/value evidence, including localized field names.

    Key names are intentionally preserved because DxDiag follows the Windows
    display language.  English aliases below are conveniences, not guesses.
    """
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    lines = text.splitlines()
    # DxDiag uses a three-line heading (dashes, title, dashes), rather than a
    # one-line heading.  Only Direct3D-relevant sections are retained: a full
    # report also carries unrelated crash, media, input, and audio inventories.
    index = 0
    while index < len(lines):
        if (re.fullmatch(r"\s*-{5,}\s*", lines[index]) and index + 2 < len(lines)
                and re.fullmatch(r"\s*-{5,}\s*", lines[index + 2])):
            title = lines[index + 1].strip()
            relevant = bool(re.search(r"display|system information|directx files|diagnostics", title, re.IGNORECASE))
            current = title if title and relevant else None
            if current:
                sections.setdefault(current, {})
            index += 3
            continue
        field = _DXDIAG_FIELD.match(lines[index])
        if current and field:
            key, value = field.groups()
            # Duplicate keys occur in multi-display reports; preserve all.
            old = sections[current].get(key)
            sections[current][key] = value if old is None else old + " | " + value
        index += 1
    feature_levels: list[str] = []
    directx_version = None
    for fields in sections.values():
        for key, value in fields.items():
            low = key.lower()
            if "feature level" in low:
                feature_levels.extend(re.findall(r"\b(?:\d+_\d+|\d+\.\d+)\b", value))
            if directx_version is None and "directx version" in low:
                directx_version = value
    return {"directx_version": directx_version, "feature_levels": list(dict.fromkeys(feature_levels)), "sections": sections}


def collect_direct3d_info(skip_dxdiag: bool = False) -> dict[str, Any]:
    """Collect a stable Direct3D report; no renderer or test device is created."""
    windows = sys.platform == "win32"
    report: dict[str, Any] = {
        "platform": {"operating_system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "direct3d": {
            "supported_platform": windows,
            "availability": "not_applicable" if not windows else "unknown",
            "runtime": {"registry": {}, "dxdiag_version": None},
            "adapters": [],
            "feature_levels": [],
            "dxdiag": {"attempted": False, "source": None, "sections": {}},
            "limitations": [],
        },
    }
    d3d = report["direct3d"]
    if not windows:
        d3d["limitations"].append("Direct3D is a Windows API; no compatibility layer is probed on this platform.")
        return report
    inventory, source = _windows_inventory()
    d3d["adapters"] = [_normalize_adapter(item) for item in _list(inventory.get("adapters"))]
    d3d["runtime"]["registry"] = inventory.get("directx") or {}
    d3d["operating_system"] = inventory.get("os") or {}
    if source == "unavailable":
        d3d["limitations"].append("PowerShell/CIM inventory was unavailable or denied.")
    else:
        d3d["availability"] = "runtime_registry_or_adapter_inventory_exposed" if d3d["adapters"] or d3d["runtime"]["registry"] else "unknown"
    if skip_dxdiag:
        d3d["limitations"].append("DxDiag was skipped; exact feature levels were not queried.")
        return report
    raw, dx_source = _dxdiag_text()
    d3d["dxdiag"]["attempted"] = True
    d3d["dxdiag"]["source"] = dx_source
    if raw is None:
        d3d["limitations"].append("DxDiag did not provide a report; feature levels and diagnostics remain unreported.")
        return report
    parsed = _parse_dxdiag(raw)
    d3d["runtime"]["dxdiag_version"] = parsed["directx_version"]
    d3d["feature_levels"] = parsed["feature_levels"]
    d3d["dxdiag"]["sections"] = parsed["sections"]
    if parsed["feature_levels"]:
        d3d["availability"] = "feature_levels_reported_by_dxdiag"
    else:
        d3d["limitations"].append("DxDiag report contained no parseable feature-level field (it may be localized or unavailable).")
    return _compact(report)


def _print_human(report: dict[str, Any]) -> None:
    d3d = report["direct3d"]
    print("Direct3D: %s" % d3d["availability"])
    print("Platform supported: %s" % d3d["supported_platform"])
    print("Adapters (%d): %s" % (len(d3d.get("adapters", [])), "; ".join(str(x.get("name", "unknown")) for x in d3d.get("adapters", [])) or "not reported"))
    print("Feature levels: %s" % (", ".join(d3d.get("feature_levels", [])) or "not reported"))
    print("DxDiag: %s" % d3d["dxdiag"].get("source", "not attempted"))
    for limitation in d3d.get("limitations", []):
        print("Note: %s" % limitation)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report Windows Direct3D runtime, adapter, driver, and DxDiag information.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON report")
    parser.add_argument("--skip-dxdiag", action="store_true", help="do not launch DxDiag or create its temporary report")
    args = parser.parse_args()
    report = collect_direct3d_info(skip_dxdiag=args.skip_dxdiag)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
