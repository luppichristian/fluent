#!/usr/bin/env python3
# description: Cross-platform CPU hardware, instruction-set, cache, and utilization inspector.
"""Report CPU hardware, instruction-set support, and current utilization.

This script deliberately uses only the Python standard library.  If ``psutil``
is installed it enriches frequency and utilization readings, but it is never a
required dependency.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _run(*command: str) -> str | None:
    """Run an optional platform command without surfacing its failures."""
    if not shutil.which(command[0]):
        return None
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return None


def _linux_cpuinfo() -> dict[str, Any]:
    text = _read_text(Path("/proc/cpuinfo")) or ""
    sections = [section for section in text.split("\n\n") if section.strip()]
    records: list[dict[str, str]] = []
    for section in sections:
        record: dict[str, str] = {}
        for line in section.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                record[key.strip().lower()] = value.strip()
        if record:
            records.append(record)

    first = records[0] if records else {}
    flags = {
        flag
        for record in records
        for flag in record.get("flags", record.get("features", "")).split()
    }
    model = first.get("model name", first.get("hardware", first.get("processor")))
    frequency = _as_float(first.get("cpu mhz"))
    physical_pairs = {
        (record.get("physical id"), record.get("core id"))
        for record in records
        if record.get("physical id") is not None and record.get("core id") is not None
    }
    sockets = {record.get("physical id") for record in records if record.get("physical id") is not None}

    caches: dict[str, list[str]] = defaultdict(list)
    for cache_path in Path("/sys/devices/system/cpu/cpu0/cache").glob("index*"):
        level = _read_text(cache_path / "level")
        size = _read_text(cache_path / "size")
        cache_type = _read_text(cache_path / "type")
        if level and size:
            label = "L%s%s" % (level.strip(), " " + cache_type.strip().lower() if cache_type else "")
            caches[label].append(size.strip())

    return {
        "name": model,
        "vendor": first.get("vendor_id"),
        "family": first.get("cpu family"),
        "model_id": first.get("model"),
        "stepping": first.get("stepping"),
        "sockets": len(sockets) or None,
        "physical_cores": len(physical_pairs) or None,
        "frequency_mhz": {"current": frequency} if frequency is not None else {},
        "cache": dict(caches),
        "instruction_sets": sorted(flags),
    }


def _macos_cpuinfo() -> dict[str, Any]:
    def sysctl(name: str) -> str | None:
        value = _run("sysctl", "-n", name)
        return value.strip() if value else None

    flags: set[str] = set()
    for name in ("machdep.cpu.features", "machdep.cpu.leaf7_features", "machdep.cpu.extfeatures"):
        value = sysctl(name)
        if value:
            flags.update(value.lower().split())
    # Apple Silicon exposes individual ISA capabilities under hw.optional.*.
    all_values = _run("sysctl", "-a") or ""
    for line in all_values.splitlines():
        match = re.match(r"hw\.optional\.([\w.]+):\s*1$", line)
        if match:
            flags.add(match.group(1).lower())

    frequency: dict[str, float] = {}
    for key, label in (("hw.cpufrequency", "current"), ("hw.cpufrequency_max", "max")):
        value = _as_float(sysctl(key))
        if value is not None:
            frequency[label] = value / 1_000_000
    return {
        "name": sysctl("machdep.cpu.brand_string") or sysctl("hw.model"),
        "vendor": sysctl("machdep.cpu.vendor"),
        "physical_cores": _as_int(sysctl("hw.physicalcpu")),
        "logical_cores": _as_int(sysctl("hw.logicalcpu")),
        "frequency_mhz": frequency,
        "cache": {
            "L1 data": _format_bytes(_as_int(sysctl("hw.l1dcachesize"))),
            "L1 instruction": _format_bytes(_as_int(sysctl("hw.l1icachesize"))),
            "L2": _format_bytes(_as_int(sysctl("hw.l2cachesize"))),
            "L3": _format_bytes(_as_int(sysctl("hw.l3cachesize"))),
        },
        "instruction_sets": sorted(flags),
    }


def _windows_cpuinfo() -> dict[str, Any]:
    """Use CPUID for ISA flags and CIM for topology/cache inventory."""
    info: dict[str, Any] = {"instruction_sets": _windows_instruction_sets()}
    command = (
        "$c=@(Get-CimInstance Win32_Processor | Select-Object "
        "Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed,"
        "L2CacheSize,L3CacheSize,SocketDesignation); $c | ConvertTo-Json -Compress"
    )
    raw = _run("powershell", "-NoProfile", "-NonInteractive", "-Command", command)
    if raw:
        try:
            records = json.loads(raw)
            if isinstance(records, dict):
                records = [records]
            data = records[0] if records else {}
            info.update(
                {
                    "name": data.get("Name"),
                    "vendor": data.get("Manufacturer"),
                    "physical_cores": sum(
                        value for item in records if (value := _as_int(item.get("NumberOfCores"))) is not None
                    ) or None,
                    "logical_cores": sum(
                        value for item in records if (value := _as_int(item.get("NumberOfLogicalProcessors"))) is not None
                    ) or None,
                    "sockets": len(records) or None,
                    "frequency_mhz": {"max": data["MaxClockSpeed"]} if data.get("MaxClockSpeed") else {},
                    "cache": {
                        "L2": _format_kib(data.get("L2CacheSize")),
                        "L3": _format_kib(data.get("L3CacheSize")),
                    },
                }
            )
        except json.JSONDecodeError:
            pass
    return info


def _windows_instruction_sets() -> list[str]:
    """Read CPUID feature leaves, falling back to Windows' limited feature API.

    CPUID is the processor's authoritative x86 feature interface.  Windows'
    IsProcessorFeaturePresent API intentionally exposes only a small subset,
    so using it alone would omit common extensions such as AVX2 and AES.
    """
    features = _windows_cpuid_instruction_sets()
    if features:
        return sorted(features)
    x86_features = {
        3: "mmx", 6: "sse", 7: "3dnow", 8: "rdtsc", 10: "sse2", 13: "sse3",
        14: "cmpxchg16b", 17: "xsave", 22: "fsgsbase", 28: "rdrand", 32: "rdtscp",
    }
    arm_features = {19: "neon", 24: "arm_divide", 29: "armv8", 30: "armv8_crypto", 31: "armv8_crc32", 36: "sve"}
    features = arm_features if platform.machine().lower().startswith("arm") else x86_features
    try:
        api = ctypes.windll.kernel32.IsProcessorFeaturePresent
        return [name for flag, name in features.items() if api(flag)]
    except (AttributeError, OSError):
        return []


def _windows_cpuid_instruction_sets() -> set[str]:
    """Call the x86 CPUID instruction through a tiny Windows x64 ABI shim."""
    if platform.machine().lower() not in {"amd64", "x86_64"}:
        return set()
    # push rbx; move (leaf, subleaf) into EAX/ECX; CPUID; save EAX..EDX to
    # the output pointer in R8; restore RBX; return.  Windows x64 ABI.
    machine_code = bytes.fromhex("53 4D 89 C1 8B C1 8B CA 0F A2 41 89 01 41 89 59 04 41 89 49 08 41 89 51 0C 5B C3")
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualAlloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong)
        kernel32.VirtualAlloc.restype = ctypes.c_void_p
        kernel32.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong)
        kernel32.VirtualFree.restype = ctypes.c_int
        address = kernel32.VirtualAlloc(None, len(machine_code), 0x3000, 0x40)
        if not address:
            return set()
        try:
            ctypes.memmove(address, machine_code, len(machine_code))
            function = ctypes.WINFUNCTYPE(None, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32))(address)

            def cpuid(leaf: int, subleaf: int = 0) -> tuple[int, int, int, int]:
                values = (ctypes.c_uint32 * 4)()
                function(leaf, subleaf, values)
                return tuple(values)

            highest, _, _, _ = cpuid(0)
            _, _, leaf1_ecx, leaf1_edx = cpuid(1)
            flags = _cpuid_flags(leaf1_edx, _CPUID_LEAF1_EDX) | _cpuid_flags(leaf1_ecx, _CPUID_LEAF1_ECX)
            if highest >= 7:
                _, leaf7_ebx, leaf7_ecx, leaf7_edx = cpuid(7)
                flags |= _cpuid_flags(leaf7_ebx, _CPUID_LEAF7_EBX)
                flags |= _cpuid_flags(leaf7_ecx, _CPUID_LEAF7_ECX)
                flags |= _cpuid_flags(leaf7_edx, _CPUID_LEAF7_EDX)
            extended_highest, _, _, _ = cpuid(0x80000000)
            if extended_highest >= 0x80000001:
                _, _, extended_ecx, extended_edx = cpuid(0x80000001)
                flags |= _cpuid_flags(extended_ecx, _CPUID_EXTENDED_ECX)
                flags |= _cpuid_flags(extended_edx, _CPUID_EXTENDED_EDX)
            return flags
        finally:
            kernel32.VirtualFree(address, 0, 0x8000)
    except (AttributeError, OSError, ValueError):
        return set()


def _cpuid_flags(value: int, names: dict[int, str]) -> set[str]:
    return {name for bit, name in names.items() if value & (1 << bit)}


_CPUID_LEAF1_EDX = {0: "fpu", 1: "vme", 2: "de", 3: "pse", 4: "tsc", 5: "msr", 6: "pae", 7: "mce", 8: "cx8", 9: "apic", 11: "sep", 12: "mtrr", 13: "pge", 14: "mca", 15: "cmov", 16: "pat", 17: "pse36", 19: "clflush", 23: "mmx", 24: "fxsr", 25: "sse", 26: "sse2", 28: "htt"}
_CPUID_LEAF1_ECX = {0: "sse3", 1: "pclmulqdq", 3: "monitor", 5: "vmx", 7: "est", 9: "ssse3", 12: "fma", 13: "cmpxchg16b", 17: "pcid", 19: "sse4_1", 20: "sse4_2", 22: "movbe", 23: "popcnt", 25: "aes", 26: "xsave", 27: "osxsave", 28: "avx", 29: "f16c", 30: "rdrand"}
_CPUID_LEAF7_EBX = {0: "fsgsbase", 2: "sgx", 3: "bmi1", 4: "hle", 5: "avx2", 7: "smep", 8: "bmi2", 9: "erms", 10: "invpcid", 11: "rtm", 16: "avx512f", 17: "avx512dq", 18: "rdseed", 19: "adx", 20: "smap", 21: "avx512ifma", 23: "clflushopt", 24: "clwb", 26: "avx512pf", 27: "avx512er", 28: "avx512cd", 29: "sha", 30: "avx512bw", 31: "avx512vl"}
_CPUID_LEAF7_ECX = {1: "avx512vbmi", 2: "umip", 3: "pku", 4: "ospke", 5: "waitpkg", 6: "avx512vbmi2", 7: "cet_ss", 8: "gfni", 9: "vaes", 10: "vpclmulqdq", 11: "avx512vnni", 12: "avx512bitalg", 14: "avx512vpopcntdq", 22: "rdpid", 25: "cldemote", 27: "movdiri", 28: "movdir64b", 29: "enqcmd"}
_CPUID_LEAF7_EDX = {2: "avx512_4vnniw", 3: "avx512_4fmaps", 4: "fsrm", 8: "avx512_vp2intersect", 14: "serialize", 16: "tsxldtrk", 18: "pconfig", 20: "ibt", 22: "amx_bf16", 23: "avx512_fp16", 24: "amx_tile", 25: "amx_int8"}
_CPUID_EXTENDED_ECX = {0: "lahf_lm", 2: "svm", 5: "abm", 6: "sse4a", 8: "3dnowprefetch", 11: "xop", 16: "fma4", 21: "tbm", 22: "topoext"}
_CPUID_EXTENDED_EDX = {11: "syscall", 20: "nx", 22: "mmxext", 27: "rdtscp", 29: "lm", 30: "3dnowext", 31: "3dnow"}


def _as_int(value: str | int | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_float(value: str | float | int | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _format_kib(value: Any) -> str | None:
    value = _as_int(value)
    return _format_bytes(value * 1024) if value is not None else None


def _format_bytes(value: int | None) -> str | None:
    if not value:
        return None
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:g} {unit}"
        value /= 1024
    return None


def _load_usage(interval: float) -> dict[str, Any]:
    """Return CPU utilization, preferring psutil but retaining useful fallbacks."""
    try:
        import psutil  # type: ignore[import-not-found]

        usage: dict[str, Any] = {
            "source": "psutil",
            "percent": psutil.cpu_percent(interval=interval),
            "per_cpu_percent": psutil.cpu_percent(interval=None, percpu=True),
        }
        frequencies = psutil.cpu_freq(percpu=False)
        if frequencies:
            usage["frequency_mhz"] = {"current": frequencies.current, "min": frequencies.min, "max": frequencies.max}
        return usage
    # psutil is an optional enhancement.  Its probes may fail under restricted
    # containers or endpoint policies, in which case native fallbacks still
    # provide a useful report.
    except (ImportError, OSError, PermissionError, ValueError, AttributeError):
        pass

    if sys.platform.startswith("linux"):
        first = _linux_jiffies()
        time.sleep(interval)
        second = _linux_jiffies()
        return {"source": "/proc/stat", "percent": _jiffies_percent(first.get("cpu"), second.get("cpu")),
                "per_cpu_percent": [_jiffies_percent(first[key], second[key]) for key in sorted(second) if key != "cpu"]}

    if sys.platform == "win32":
        first = _windows_jiffies()
        time.sleep(interval)
        second = _windows_jiffies()
        if first and second:
            idle = second[0] - first[0]
            total = (second[1] - first[1]) + (second[2] - first[2])
            return {
                "source": "GetSystemTimes",
                "percent": round((total - idle) * 100 / total, 2) if total else None,
                "per_cpu_percent": None,
            }

    usage = {"source": "unavailable", "percent": None, "per_cpu_percent": None}
    try:
        loads = os.getloadavg()
        usage["load_average"] = {"1m": loads[0], "5m": loads[1], "15m": loads[2]}
    except (AttributeError, OSError):
        pass
    return usage


def _linux_jiffies() -> dict[str, list[int]]:
    text = _read_text(Path("/proc/stat")) or ""
    values: dict[str, list[int]] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not re.fullmatch(r"cpu\d*", parts[0]):
            continue
        values[parts[0]] = [int(value) for value in parts[1:]]
    return values


def _windows_jiffies() -> tuple[int, int, int] | None:
    """Read system-wide idle, kernel, and user time in 100 ns units."""
    class FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_ulong), ("high", ctypes.c_ulong)]

    try:
        idle, kernel, user = FileTime(), FileTime(), FileTime()
        if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            return None
        return tuple((value.high << 32) | value.low for value in (idle, kernel, user))
    except (AttributeError, OSError):
        return None


def _jiffies_percent(first: list[int] | None, second: list[int] | None) -> float | None:
    if not first or not second:
        return None
    total = sum(second) - sum(first)
    idle = (second[3] + (second[4] if len(second) > 4 else 0)) - (first[3] + (first[4] if len(first) > 4 else 0))
    return round((total - idle) * 100 / total, 2) if total else None


def collect_cpu_info(interval: float, include_usage: bool) -> dict[str, Any]:
    system = platform.system()
    platform_info: dict[str, Any] = {
        "operating_system": system,
        "operating_system_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or None,
        "python_architecture": platform.architecture()[0],
    }
    if system == "Linux":
        cpu = _linux_cpuinfo()
    elif system == "Darwin":
        cpu = _macos_cpuinfo()
    elif system == "Windows":
        cpu = _windows_cpuinfo()
    else:
        cpu = {"instruction_sets": []}

    logical = os.cpu_count()
    cpu["logical_cores"] = cpu.get("logical_cores") or logical
    reported_physical_cores = cpu.get("physical_cores")
    cpu["physical_cores"] = reported_physical_cores or logical
    cpu["physical_cores_estimated"] = reported_physical_cores is None
    if include_usage:
        cpu["usage"] = _load_usage(interval)
    return {"platform": platform_info, "cpu": cpu}


def _print_human(info: dict[str, Any]) -> None:
    platform_info = info["platform"]
    cpu = info["cpu"]
    print(f"CPU: {cpu.get('name') or platform_info.get('processor') or 'Unknown'}")
    print(f"Platform: {platform_info['operating_system']} {platform_info['operating_system_release']} ({platform_info['machine']})")
    print(f"Cores: {cpu.get('physical_cores')} physical, {cpu.get('logical_cores')} logical")
    if cpu.get("frequency_mhz"):
        print("Frequency (MHz): " + ", ".join(f"{key}={value}" for key, value in cpu["frequency_mhz"].items() if value is not None))
    if cpu.get("cache"):
        print("Cache: " + ", ".join(f"{key}={value}" for key, value in cpu["cache"].items() if value))
    usage = cpu.get("usage")
    if usage:
        print(f"CPU usage: {usage.get('percent')}% ({usage.get('source')})")
        if usage.get("load_average"):
            print("Load average: " + ", ".join(f"{key}={value}" for key, value in usage["load_average"].items()))
    flags = cpu.get("instruction_sets", [])
    print(f"Instruction sets ({len(flags)}): {' '.join(flags) if flags else 'not discoverable on this platform'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Report cross-platform CPU hardware, ISA capabilities, and current utilization.")
    parser.add_argument("--json", action="store_true", help="emit one JSON object for programs and LLM tool calls")
    parser.add_argument("--no-usage", action="store_true", help="skip the short utilization sample")
    parser.add_argument("--interval", type=float, default=0.2, metavar="SECONDS", help="usage sample duration (default: 0.2; must be non-negative)")
    args = parser.parse_args()
    if args.interval < 0:
        parser.error("--interval must be non-negative")
    info = collect_cpu_info(args.interval, not args.no_usage)
    if args.json:
        print(json.dumps(info, indent=2, sort_keys=True, default=str))
    else:
        _print_human(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
