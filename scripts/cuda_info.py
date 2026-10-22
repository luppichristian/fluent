#!/usr/bin/env python3
# description: Cross-platform CUDA driver, toolkit, and NVIDIA GPU capability inspector.
"""Inspect CUDA without requiring the CUDA toolkit or a Python package.

The CUDA Driver API is loaded with :mod:`ctypes` when it is installed.  This
means the report can enumerate detailed device limits even on machines that
have a display driver but no ``nvcc`` compiler.  Every probe is best effort:
unsupported systems return the same JSON shape with availability information.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _run(*command: str) -> tuple[str | None, int | None]:
    if not command or not shutil.which(command[0]):
        return None, None
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        return result.stdout, result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return None, None


def _version(value: int | None) -> str | None:
    if value is None:
        return None
    # NVIDIA encodes 12040 as CUDA 12.4, 11080 as CUDA 11.8, etc.
    return f"{value // 1000}.{(value % 1000) // 10}" if value >= 1000 else str(value)


def _candidate_roots() -> list[str]:
    roots: list[Path] = []
    for name in ("CUDA_PATH", "CUDA_HOME", "CUDA_ROOT"):
        if os.environ.get(name):
            roots.append(Path(os.environ[name]))
    if sys.platform == "win32":
        base = Path(os.environ.get("ProgramFiles", r"C:\\Program Files")) / "NVIDIA GPU Computing Toolkit" / "CUDA"
        if base.is_dir():
            roots.extend(item for item in base.iterdir() if item.is_dir())
    elif sys.platform.startswith("linux"):
        roots.extend(Path(item) for item in ("/usr/local/cuda", "/opt/cuda") if Path(item).is_dir())
        roots.extend(sorted(Path("/usr/local").glob("cuda-*")))
    elif sys.platform == "darwin":
        roots.extend(Path(item) for item in ("/usr/local/cuda", "/Developer/NVIDIA/CUDA-*/") if Path(item).exists())
    return sorted({str(path.resolve()) for path in roots if path.exists()})


def _library_candidates(roots: list[str]) -> list[str]:
    names = ("cudart64*.dll", "cudart*.dll") if sys.platform == "win32" else ("libcudart.so*", "libcuda.so*")
    values: set[str] = set()
    for root in roots:
        for directory in (Path(root) / "bin", Path(root) / "lib", Path(root) / "lib64"):
            if directory.is_dir():
                for pattern in names:
                    values.update(str(path) for path in directory.glob(pattern))
    for library in (ctypes.util.find_library("cudart"), ctypes.util.find_library("cuda")):
        if library:
            values.add(library)
    return sorted(values)


def _load_driver() -> tuple[Any | None, str | None]:
    names = ["nvcuda.dll"] if sys.platform == "win32" else ["libcuda.so.1", "libcuda.so"]
    located = ctypes.util.find_library("cuda")
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == "win32" else ctypes.CDLL
    for name in names:
        try:
            return loader(name), name
        except OSError:
            continue
    return None, None


def _driver_api() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    base = {"available": False, "library": None, "status": "CUDA Driver API library was not found", "driver_version_raw": None, "driver_version": None}
    library, library_name = _load_driver()
    base["library"] = library_name
    if library is None:
        return base, []
    try:
        library.cuInit.argtypes = [ctypes.c_uint]
        library.cuInit.restype = ctypes.c_int
        result = library.cuInit(0)
        if result != 0:
            base["status"] = f"cuInit failed with CUDA result {result}"
            return base, []
        library.cuDriverGetVersion.argtypes = [ctypes.POINTER(ctypes.c_int)]
        library.cuDriverGetVersion.restype = ctypes.c_int
        version = ctypes.c_int()
        if library.cuDriverGetVersion(ctypes.byref(version)) == 0:
            base["driver_version_raw"] = version.value
            base["driver_version"] = _version(version.value)
        library.cuDeviceGetCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
        library.cuDeviceGetCount.restype = ctypes.c_int
        count = ctypes.c_int()
        if library.cuDeviceGetCount(ctypes.byref(count)) != 0:
            base["status"] = "CUDA driver initialized but device enumeration failed"
            return base, []
        base.update({"available": True, "status": "available", "device_count": count.value})
        library.cuDeviceGet.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        library.cuDeviceGet.restype = ctypes.c_int
        library.cuDeviceGetName.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        library.cuDeviceGetName.restype = ctypes.c_int
        library.cuDeviceComputeCapability.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        library.cuDeviceComputeCapability.restype = ctypes.c_int
        library.cuDeviceGetAttribute.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.c_int]
        library.cuDeviceGetAttribute.restype = ctypes.c_int
        total_memory = getattr(library, "cuDeviceTotalMem_v2", None)
        if total_memory is None:
            total_memory = getattr(library, "cuDeviceTotalMem", None)
        if total_memory:
            total_memory.argtypes = [ctypes.POINTER(ctypes.c_size_t), ctypes.c_int]
            total_memory.restype = ctypes.c_int
        attributes = {
            "max_threads_per_block": 1, "max_block_dimensions": (2, 3, 4), "max_grid_dimensions": (5, 6, 7),
            "max_shared_memory_per_block_bytes": 8, "total_constant_memory_bytes": 9, "warp_size": 10,
            "max_registers_per_block": 12, "clock_rate_khz": 13, "texture_alignment_bytes": 14,
            "gpu_overlap": 15, "multiprocessor_count": 16, "kernel_execution_timeout": 17,
            "integrated": 18, "can_map_host_memory": 19, "compute_mode": 20, "unified_addressing": 41,
            "pci_bus_id": 33, "pci_device_id": 34, "pci_domain_id": 50, "ecc_enabled": 32,
            "concurrent_kernels": 31, "managed_memory": 83, "concurrent_managed_access": 89,
            "pageable_memory_access": 88, "memory_pools_supported": 115, "virtual_memory_management_supported": 102,
        }
        devices: list[dict[str, Any]] = []
        for index in range(count.value):
            device = ctypes.c_int()
            if library.cuDeviceGet(ctypes.byref(device), index) != 0:
                continue
            name = ctypes.create_string_buffer(256)
            library.cuDeviceGetName(name, len(name), device.value)
            major, minor = ctypes.c_int(), ctypes.c_int()
            library.cuDeviceComputeCapability(ctypes.byref(major), ctypes.byref(minor), device.value)
            limits: dict[str, Any] = {}
            for label, identifier in attributes.items():
                if isinstance(identifier, tuple):
                    values: list[int | None] = []
                    for item in identifier:
                        output = ctypes.c_int()
                        values.append(output.value if library.cuDeviceGetAttribute(ctypes.byref(output), item, device.value) == 0 else None)
                    limits[label] = values
                else:
                    output = ctypes.c_int()
                    if library.cuDeviceGetAttribute(ctypes.byref(output), identifier, device.value) == 0:
                        limits[label] = output.value
            memory = ctypes.c_size_t()
            devices.append({
                "index": index, "name": name.value.decode(errors="replace") or None,
                "compute_capability": f"{major.value}.{minor.value}" if major.value or minor.value else None,
                "total_memory_bytes": memory.value if total_memory and total_memory(ctypes.byref(memory), device.value) == 0 else None,
                "driver_api_limits": limits,
            })
        return base, devices
    except (AttributeError, OSError, ValueError) as error:
        base["status"] = f"Driver API probe failed: {type(error).__name__}"
        return base, []


def _nvidia_smi() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = shutil.which("nvidia-smi")
    probe: dict[str, Any] = {"available": False, "path": path, "status": "nvidia-smi was not found", "cuda_version": None}
    if not path:
        return probe, []
    fields = "index,name,uuid,pci.bus_id,driver_version,vbios_version,compute_cap,memory.total,memory.free,memory.used,temperature.gpu,power.limit,pstate,compute_mode,persistence_mode"
    output, status = _run(path, f"--query-gpu={fields}", "--format=csv,noheader,nounits")
    header, _ = _run(path)
    if header:
        # Recent NVIDIA-SMI builds label this as "CUDA UMD Version", while
        # older builds use "CUDA Version". Both describe the driver's CUDA
        # user-mode API compatibility, not necessarily an installed toolkit.
        match = re.search(r"CUDA(?:\s+UMD)?\s+Version:\s*([\d.]+)", header)
        probe["cuda_version"] = match.group(1) if match else None
    if status != 0 or output is None:
        probe["status"] = f"nvidia-smi query failed (exit {status})"
        return probe, []
    devices: list[dict[str, Any]] = []
    for row in output.splitlines():
        values = [item.strip() for item in row.split(",")]
        if len(values) != len(fields.split(",")):
            continue
        item = dict(zip(fields.split(","), values))
        devices.append({
            "index": _integer(item["index"]), "name": item["name"], "uuid": item["uuid"], "pci_bus_id": item["pci.bus_id"],
            "driver_version": item["driver_version"], "vbios_version": item["vbios_version"], "compute_capability": _none(item["compute_cap"]),
            "memory_total_mib": _integer(item["memory.total"]), "memory_free_mib": _integer(item["memory.free"]), "memory_used_mib": _integer(item["memory.used"]),
            "temperature_celsius": _integer(item["temperature.gpu"]), "power_limit_watts": _number(item["power.limit"]), "performance_state": _none(item["pstate"]),
            "compute_mode": _none(item["compute_mode"]), "persistence_mode": _none(item["persistence_mode"]),
        })
    probe.update({"available": True, "status": "available", "device_count": len(devices)})
    return probe, devices


def _none(value: str | None) -> str | None:
    return None if value is None or value.strip().upper() in {"N/A", "[NOT SUPPORTED]", ""} else value


def _integer(value: str | None) -> int | None:
    try:
        return int(value) if _none(value) is not None else None
    except (TypeError, ValueError):
        return None


def _number(value: str | None) -> float | None:
    try:
        return float(value) if _none(value) is not None else None
    except (TypeError, ValueError):
        return None


def _merge_devices(driver_devices: list[dict[str, Any]], smi_devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not driver_devices:
        return [{"index": item.get("index"), "name": item.get("name"), "driver_api": {}, "nvidia_smi": item} for item in smi_devices]
    by_index = {item.get("index"): item for item in smi_devices}
    report: list[dict[str, Any]] = []
    for item in driver_devices:
        report.append({"index": item.get("index"), "name": item.get("name"), "compute_capability": item.get("compute_capability"), "total_memory_bytes": item.get("total_memory_bytes"), "driver_api": item.get("driver_api_limits", {}), "nvidia_smi": by_index.pop(item.get("index"), {})})
    report.extend({"index": item.get("index"), "name": item.get("name"), "driver_api": {}, "nvidia_smi": item} for item in by_index.values())
    return report


def collect_cuda_info() -> dict[str, Any]:
    roots = _candidate_roots()
    driver, driver_devices = _driver_api()
    smi, smi_devices = _nvidia_smi()
    nvcc_path = shutil.which("nvcc")
    nvcc_output, nvcc_status = _run(nvcc_path, "--version") if nvcc_path else (None, None)
    match = re.search(r"release\s+([\d.]+).*?V([\d.]+)", nvcc_output or "", re.S)
    compiler = {"available": bool(nvcc_path and nvcc_status == 0), "path": nvcc_path, "release": match.group(1) if match else None, "build_version": match.group(2) if match else None, "status": "available" if nvcc_path and nvcc_status == 0 else ("nvcc not found" if not nvcc_path else f"nvcc failed (exit {nvcc_status})")}
    return {
        "schema_version": 1,
        "platform": {"operating_system": platform.system(), "operating_system_release": platform.release(), "machine": platform.machine()},
        "availability": {"cuda_driver_api": driver["available"], "nvidia_smi": smi["available"], "compiler": compiler["available"], "detected": bool(driver["available"] or smi["available"])},
        "probes": {"cuda_driver_api": driver, "nvidia_smi": smi, "nvcc": compiler},
        "installations": {"environment": {name: os.environ.get(name) for name in ("CUDA_PATH", "CUDA_HOME", "CUDA_ROOT") if os.environ.get(name)}, "candidate_roots": roots, "runtime_libraries": _library_candidates(roots)},
        "driver": {"cuda_driver_version": driver.get("driver_version"), "cuda_driver_version_raw": driver.get("driver_version_raw"), "nvidia_smi_cuda_version": smi.get("cuda_version")},
        "devices": _merge_devices(driver_devices, smi_devices),
    }


def _human(report: dict[str, Any]) -> None:
    availability = report["availability"]
    print("CUDA: " + ("detected" if availability["detected"] else "not detected"))
    print("Driver API: %s | nvidia-smi: %s | nvcc: %s" % (availability["cuda_driver_api"], availability["nvidia_smi"], availability["compiler"]))
    print("Driver CUDA version: %s | nvidia-smi CUDA version: %s" % (report["driver"]["cuda_driver_version"] or "unknown", report["driver"]["nvidia_smi_cuda_version"] or "unknown"))
    for device in report["devices"]:
        smi = device.get("nvidia_smi", {})
        print("GPU %s: %s | CC %s | memory %s MiB | SMs %s" % (device.get("index"), device.get("name") or "unknown", device.get("compute_capability") or smi.get("compute_capability") or "unknown", smi.get("memory_total_mib") or (device.get("total_memory_bytes") // (1024 * 1024) if device.get("total_memory_bytes") else "unknown"), device.get("driver_api", {}).get("multiprocessor_count", "unknown")))
    if not report["devices"]:
        print("No CUDA devices were enumerated. See --json probes for the reason.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Report CUDA driver, toolkit, GPU capability, and configuration information.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_cuda_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
