#!/usr/bin/env python3
# description: Cross-platform system hardware inventory, excluding detailed CPU analysis.
"""Report a best-effort, dependency-free hardware inventory.

The collector is intentionally read-only and uses only Python's standard
library.  OS commands are optional probes: missing tools, permissions, or
virtual machines result in empty values rather than failed reports.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _read(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _run(*command: str) -> str | None:
    """Return optional command output, never propagating host probe failures."""
    if not command or not shutil.which(command[0]):
        return None
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL, timeout=12)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def _number(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _json_command(*command: str) -> Any:
    text = _run(*command)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _compact(value: Any) -> Any:
    """Remove unavailable leaves but retain empty lists/dicts for stable sections."""
    if isinstance(value, dict):
        return {key: _compact(item) for key, item in value.items() if item not in (None, "")}
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


def _sys_value(name: str) -> str | None:
    value = _read(Path("/sys/class/dmi/id") / name)
    return value or None


def _linux_dmi() -> dict[str, Any]:
    return _compact({
        "chassis": {"manufacturer": _sys_value("chassis_vendor"), "type": _sys_value("chassis_type"), "version": _sys_value("chassis_version"), "serial": _sys_value("chassis_serial")},
        "baseboard": {"manufacturer": _sys_value("board_vendor"), "product": _sys_value("board_name"), "version": _sys_value("board_version"), "serial": _sys_value("board_serial")},
        "bios": {"vendor": _sys_value("bios_vendor"), "version": _sys_value("bios_version"), "date": _sys_value("bios_date")},
        "computer": {"manufacturer": _sys_value("sys_vendor"), "product": _sys_value("product_name"), "version": _sys_value("product_version"), "serial": _sys_value("product_serial"), "uuid": _sys_value("product_uuid")},
    })


def _linux_memory() -> dict[str, Any]:
    values: dict[str, int] = {}
    for line in (_read("/proc/meminfo") or "").splitlines():
        match = re.match(r"([^:]+):\s+(\d+)\s+kB", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    modules: list[dict[str, Any]] = []
    # dmidecode exposes DIMM identity, but is often root-only; do not require it.
    raw = _run("dmidecode", "--type", "memory")
    if raw:
        block: dict[str, str] = {}
        for line in raw.splitlines() + [""]:
            if line.startswith("\t") and ":" in line:
                key, value = line.strip().split(":", 1)
                block[key] = value.strip()
            elif not line.strip() and block:
                if block.get("Size") not in (None, "No Module Installed"):
                    modules.append(_compact({"locator": block.get("Locator"), "bank": block.get("Bank Locator"), "size": block.get("Size"), "type": block.get("Type"), "speed": block.get("Configured Memory Speed") or block.get("Speed"), "manufacturer": block.get("Manufacturer"), "part_number": block.get("Part Number"), "serial": block.get("Serial Number")}))
                block = {}
    return {"total_bytes": values.get("MemTotal"), "available_bytes": values.get("MemAvailable"), "swap_total_bytes": values.get("SwapTotal"), "swap_free_bytes": values.get("SwapFree"), "modules": modules}


def _linux_storage() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = _json_command("lsblk", "--bytes", "--json", "--output", "NAME,KNAME,TYPE,SIZE,MODEL,VENDOR,SERIAL,TRAN,ROTA,MOUNTPOINTS,FSTYPE") or {}
    disks: list[dict[str, Any]] = []
    filesystems: list[dict[str, Any]] = []
    def visit(item: dict[str, Any], parent: str | None = None) -> None:
        kind = item.get("type")
        name = item.get("name")
        if kind == "disk":
            disks.append(_compact({"name": name, "path": "/dev/" + item.get("kname", name), "size_bytes": _number(item.get("size")), "model": item.get("model"), "vendor": item.get("vendor"), "serial": item.get("serial"), "transport": item.get("tran"), "rotational": str(item.get("rota")).lower() in {"1", "true"}, "removable": _read("/sys/block/%s/removable" % item.get("kname", "")) == "1"}))
        mounts = item.get("mountpoints") or []
        for mount in mounts:
            if mount:
                filesystems.append(_compact({"device": "/dev/" + item.get("kname", name), "mountpoint": mount, "type": item.get("fstype"), "size_bytes": _number(item.get("size")), "parent": parent}))
        for child in item.get("children") or []:
            visit(child, name or parent)
    for device in data.get("blockdevices", []):
        visit(device)
    return disks, filesystems


def _linux_graphics() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    gpus: list[dict[str, Any]] = []
    for line in (_run("lspci", "-mm") or "").splitlines():
        if not re.search(r'"(?:VGA compatible controller|3D controller|Display controller)"', line, re.I):
            continue
        fields = re.findall(r'"([^"]*)"', line)
        gpus.append(_compact({"bus": line.split()[0] if line.split() else None, "class": fields[0] if fields else None, "vendor": fields[1] if len(fields) > 1 else None, "model": fields[2] if len(fields) > 2 else None}))
    displays = []
    for output in (_run("xrandr", "--query") or "").splitlines():
        match = re.match(r"(\S+) connected(?: primary)? (\d+x\d+\+\d+\+\d+)?", output)
        if match:
            displays.append({"name": match.group(1), "current_mode": match.group(2)})
    return gpus, displays


def _linux_network() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in Path("/sys/class/net").glob("*"):
        name = path.name
        if name == "lo":
            continue
        records.append(_compact({"name": name, "mac_address": _read(path / "address"), "state": _read(path / "operstate"), "speed_mbps": _number(_read(path / "speed")), "duplex": _read(path / "duplex"), "type": _read(path / "type"), "wireless": (path / "wireless").exists()}))
    return records


def _linux_power() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    batteries: list[dict[str, Any]] = []
    sensors: list[dict[str, Any]] = []
    root = Path("/sys/class/power_supply")
    for item in root.glob("*"):
        kind = _read(item / "type")
        if kind == "Battery":
            batteries.append(_compact({"name": item.name, "status": _read(item / "status"), "capacity_percent": _number(_read(item / "capacity")), "technology": _read(item / "technology"), "manufacturer": _read(item / "manufacturer"), "model": _read(item / "model_name"), "serial": _read(item / "serial_number"), "energy_now_uwh": _number(_read(item / "energy_now")), "energy_full_uwh": _number(_read(item / "energy_full"),), "power_now_uw": _number(_read(item / "power_now")), "voltage_now_uv": _number(_read(item / "voltage_now"))}))
    for zone in Path("/sys/class/thermal").glob("thermal_zone*"):
        temp = _number(_read(zone / "temp"))
        sensors.append(_compact({"name": _read(zone / "type") or zone.name, "kind": "temperature", "value_celsius": round(temp / 1000, 2) if temp is not None else None}))
    return batteries, sensors


def _powershell_inventory() -> dict[str, Any]:
    script = r'''$o=[ordered]@{}; $o.computer=Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,TotalPhysicalMemory; $o.bios=Get-CimInstance Win32_BIOS | Select Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber; $o.baseboard=Get-CimInstance Win32_BaseBoard | Select Manufacturer,Product,Version,SerialNumber; $o.chassis=Get-CimInstance Win32_SystemEnclosure | Select Manufacturer,ChassisTypes,SerialNumber; $o.memory=@(Get-CimInstance Win32_PhysicalMemory | Select DeviceLocator,BankLabel,Capacity,Speed,ConfiguredClockSpeed,Manufacturer,PartNumber,SerialNumber); $o.disks=@(Get-CimInstance Win32_DiskDrive | Select Model,SerialNumber,Size,MediaType,InterfaceType,FirmwareRevision); $o.filesystems=@(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select DeviceID,VolumeName,FileSystem,Size,FreeSpace); $o.gpus=@(Get-CimInstance Win32_VideoController | Select Name,AdapterRAM,DriverVersion,VideoModeDescription,CurrentHorizontalResolution,CurrentVerticalResolution); $o.displays=@(Get-CimInstance Win32_DesktopMonitor | Select Name,ScreenWidth,ScreenHeight,PNPDeviceID); $o.network=@(Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=True' | Select Name,MACAddress,NetConnectionStatus,Speed,Manufacturer,PNPDeviceID); $o.battery=@(Get-CimInstance Win32_Battery | Select Name,BatteryStatus,EstimatedChargeRemaining,EstimatedRunTime,Chemistry); $o | ConvertTo-Json -Depth 4 -Compress'''
    return _json_command("powershell", "-NoProfile", "-NonInteractive", "-Command", script) or {}


def _windows_info() -> dict[str, Any]:
    source = _powershell_inventory()
    def items(key: str) -> list[dict[str, Any]]:
        value = source.get(key) or []
        return value if isinstance(value, list) else [value]
    comp = source.get("computer") or {}
    bios, board, chassis = source.get("bios") or {}, source.get("baseboard") or {}, source.get("chassis") or {}
    return {
        "computer": {"manufacturer": comp.get("Manufacturer"), "product": comp.get("Model")},
        "chassis": {"manufacturer": chassis.get("Manufacturer"), "type": chassis.get("ChassisTypes"), "serial": chassis.get("SerialNumber")},
        "baseboard": {"manufacturer": board.get("Manufacturer"), "product": board.get("Product"), "version": board.get("Version"), "serial": board.get("SerialNumber")},
        "bios": {"vendor": bios.get("Manufacturer"), "version": bios.get("SMBIOSBIOSVersion"), "date": bios.get("ReleaseDate"), "serial": bios.get("SerialNumber")},
        "memory": {"total_bytes": _number(comp.get("TotalPhysicalMemory")), "available_bytes": None, "swap_total_bytes": None, "swap_free_bytes": None, "modules": [_compact({"locator": x.get("DeviceLocator"), "bank": x.get("BankLabel"), "size_bytes": _number(x.get("Capacity")), "speed_mhz": _number(x.get("ConfiguredClockSpeed")) or _number(x.get("Speed")), "manufacturer": x.get("Manufacturer"), "part_number": x.get("PartNumber"), "serial": x.get("SerialNumber")}) for x in items("memory")]},
        "storage": [_compact({"model": x.get("Model"), "serial": x.get("SerialNumber"), "size_bytes": _number(x.get("Size")), "media_type": x.get("MediaType"), "interface": x.get("InterfaceType"), "firmware": x.get("FirmwareRevision")}) for x in items("disks")],
        "filesystems": [_compact({"device": x.get("DeviceID"), "label": x.get("VolumeName"), "type": x.get("FileSystem"), "size_bytes": _number(x.get("Size")), "free_bytes": _number(x.get("FreeSpace"))}) for x in items("filesystems")],
        "graphics": [_compact({"name": x.get("Name"), "memory_bytes": _number(x.get("AdapterRAM")), "driver": x.get("DriverVersion"), "current_mode": x.get("VideoModeDescription")}) for x in items("gpus")],
        "displays": [_compact({"name": x.get("Name"), "width": _number(x.get("ScreenWidth")), "height": _number(x.get("ScreenHeight")), "id": x.get("PNPDeviceID")}) for x in items("displays")],
        "network": [_compact({"name": x.get("Name"), "mac_address": x.get("MACAddress"), "status": x.get("NetConnectionStatus"), "speed_bps": _number(x.get("Speed")), "manufacturer": x.get("Manufacturer"), "id": x.get("PNPDeviceID")}) for x in items("network")],
        "battery": [_compact({"name": x.get("Name"), "status": x.get("BatteryStatus"), "capacity_percent": _number(x.get("EstimatedChargeRemaining")), "estimated_runtime_minutes": _number(x.get("EstimatedRunTime")), "chemistry": x.get("Chemistry")}) for x in items("battery")],
        "sensors": [],
    }


def _macos_info() -> dict[str, Any]:
    # system_profiler's XML is available on every supported macOS release.
    import plistlib
    raw = _run("system_profiler", "SPHardwareDataType", "SPMemoryDataType", "SPStorageDataType", "SPDisplaysDataType", "SPNetworkDataType", "SPPowerDataType", "-xml")
    try:
        groups = plistlib.loads(raw.encode()) if raw else []
    except (ValueError, TypeError):
        groups = []
    data = {group.get("_dataType"): group.get("_items", []) for group in groups if isinstance(group, dict)}
    hardware = (data.get("SPHardwareDataType") or [{}])[0]
    memory = (data.get("SPMemoryDataType") or [{}])[0]
    graphics = data.get("SPDisplaysDataType") or []
    return {
        "computer": {"model": hardware.get("machine_model"), "model_identifier": hardware.get("machine_name"), "serial": hardware.get("serial_number")},
        "chassis": {}, "baseboard": {}, "bios": {"version": hardware.get("boot_rom_version")},
        "memory": {"total": memory.get("memory"), "modules": memory.get("_items", [])},
        "storage": data.get("SPStorageDataType") or [], "filesystems": [], "graphics": graphics, "displays": [], "network": data.get("SPNetworkDataType") or [], "battery": data.get("SPPowerDataType") or [], "sensors": [],
    }


def collect_hardware_info() -> dict[str, Any]:
    """Produce the stable public report shape without requiring privileges."""
    system = platform.system()
    if system == "Linux":
        system_data = _linux_dmi()
        disks, filesystems = _linux_storage()
        graphics, displays = _linux_graphics()
        batteries, sensors = _linux_power()
        details = {**system_data, "memory": _linux_memory(), "storage": disks, "filesystems": filesystems, "graphics": graphics, "displays": displays, "network": _linux_network(), "battery": batteries, "sensors": sensors}
    elif system == "Windows":
        details = _windows_info()
    elif system == "Darwin":
        details = _macos_info()
    else:
        details = {}
    stable = {key: details.get(key, {} if key in {"computer", "chassis", "baseboard", "bios", "memory"} else []) for key in ("computer", "chassis", "baseboard", "bios", "memory", "storage", "filesystems", "graphics", "displays", "network", "battery", "sensors")}
    return {"platform": {"operating_system": system, "operating_system_release": platform.release(), "machine": platform.machine(), "hostname": platform.node() or None}, "hardware": _compact(stable)}


def _print_human(report: dict[str, Any]) -> None:
    hardware = report["hardware"]
    computer = hardware["computer"]
    title = computer.get("product") or computer.get("model") or "Unknown"
    print("System: %s%s" % (computer.get("manufacturer") + " " if computer.get("manufacturer") else "", title))
    print("Platform: %s %s (%s)" % (report["platform"]["operating_system"], report["platform"]["operating_system_release"], report["platform"]["machine"]))
    memory = hardware["memory"]
    print("Memory: %s bytes%s" % (memory.get("total_bytes", memory.get("total", "unknown")), " (%d modules)" % len(memory.get("modules", [])) if memory.get("modules") else ""))
    for label, key in (("Storage", "storage"), ("Graphics", "graphics"), ("Network", "network"), ("Battery", "battery"), ("Sensors", "sensors")):
        values = hardware[key]
        names = [str(value.get("model") or value.get("name") or value.get("device") or "unknown") for value in values if isinstance(value, dict)]
        print("%s (%d): %s" % (label, len(values), "; ".join(names[:3]) or "not reported"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Report cross-platform hardware inventory (CPU details are in cpu_info.py).")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_hardware_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
