#!/usr/bin/env python3
# description: Cross-platform OpenCL platform, device, ICD, and capability inspector.
"""Inspect OpenCL implementations through the standard OpenCL C API.

No SDK, Python binding, compiler, or GPU is required to run this script.  It
loads the installed OpenCL loader with ctypes, then records exactly what the
loader exposes. Missing loaders, no ICDs, and failed native tools remain
reported as data rather than making the script fail.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


CL_SUCCESS = 0
CL_DEVICE_TYPE_ALL = 0xFFFFFFFF
CL_PLATFORM_NOT_FOUND_KHR = -1001

PLATFORM_INFO = {"profile": 0x0900, "version": 0x0901, "name": 0x0902, "vendor": 0x0903, "extensions": 0x0904}
STRING_PROPERTIES = {
    "name": 0x102B, "vendor": 0x102C, "driver_version": 0x102D, "profile": 0x102E,
    "device_version": 0x102F, "extensions": 0x1030, "opencl_c_version": 0x103D,
    "built_in_kernels": 0x103F, "il_version": 0x105B,
}
UINT_PROPERTIES = {
    "vendor_id": 0x1001, "max_compute_units": 0x1002, "max_work_item_dimensions": 0x1003,
    "preferred_vector_width_char": 0x1006, "preferred_vector_width_short": 0x1007,
    "preferred_vector_width_int": 0x1008, "preferred_vector_width_long": 0x1009,
    "preferred_vector_width_float": 0x100A, "preferred_vector_width_double": 0x100B,
    "max_clock_frequency_mhz": 0x100C, "address_bits": 0x100D, "max_read_image_args": 0x100E,
    "max_write_image_args": 0x100F, "max_samplers": 0x1018, "mem_base_addr_align_bits": 0x1019,
    "min_data_type_align_size": 0x101A, "global_mem_cacheline_size": 0x101D, "max_constant_args": 0x1021,
    "local_mem_type": 0x1022, "error_correction_support": 0x1024, "profiling_timer_resolution_ns": 0x1025,
    "endian_little": 0x1026, "available": 0x1027, "compiler_available": 0x1028,
    "execution_capabilities": 0x1029, "queue_properties": 0x102A, "global_mem_cache_type": 0x101C,
    "single_fp_config": 0x101B, "double_fp_config": 0x1032, "half_fp_config": 0x1033,
    "preferred_interop_user_sync": 0x1048, "partition_max_sub_devices": 0x1043,
    "partition_affinity_domain": 0x1045,
}
SIZE_PROPERTIES = {
    "max_work_group_size": 0x1004, "max_mem_alloc_size_bytes": 0x1010, "max_parameter_size_bytes": 0x1017,
    "image2d_max_width": 0x1011, "image2d_max_height": 0x1012, "image3d_max_width": 0x1013,
    "image3d_max_height": 0x1014, "image3d_max_depth": 0x1015, "max_global_variable_size_bytes": 0x104D,
    "global_variable_preferred_total_size_bytes": 0x1054,
}
ULONG_PROPERTIES = {"global_mem_cache_size_bytes": 0x101E, "global_mem_size_bytes": 0x101F, "max_constant_buffer_size_bytes": 0x1020, "local_mem_size_bytes": 0x1023, "printf_buffer_size_bytes": 0x1049, "max_pipe_args": 0x1055, "pipe_max_active_reservations": 0x1056, "pipe_max_packet_size": 0x1057, "svm_capabilities": 0x1053}


def _run(*command: str) -> tuple[str | None, int | None]:
    if not command or not shutil.which(command[0]):
        return None, None
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return result.stdout, result.returncode
    except (OSError, subprocess.TimeoutExpired):
        return None, None


def _load_opencl() -> tuple[Any | None, str | None]:
    names = ["OpenCL.dll"] if sys.platform == "win32" else (["/System/Library/Frameworks/OpenCL.framework/OpenCL"] if sys.platform == "darwin" else ["libOpenCL.so.1", "libOpenCL.so"])
    located = ctypes.util.find_library("OpenCL")
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == "win32" else ctypes.CDLL
    for name in names:
        try:
            return loader(name), name
        except OSError:
            pass
    return None, None


def _string(getter: Any, handle: Any, code: int) -> str | None:
    size = ctypes.c_size_t()
    if getter(handle, code, 0, None, ctypes.byref(size)) != CL_SUCCESS or not size.value:
        return None
    raw = ctypes.create_string_buffer(size.value)
    if getter(handle, code, size.value, raw, None) != CL_SUCCESS:
        return None
    return raw.value.decode(errors="replace").strip() or None


def _bytes(getter: Any, handle: Any, code: int) -> bytes | None:
    size = ctypes.c_size_t()
    if getter(handle, code, 0, None, ctypes.byref(size)) != CL_SUCCESS or not size.value:
        return None
    raw = (ctypes.c_ubyte * size.value)()
    return bytes(raw) if getter(handle, code, size.value, raw, None) == CL_SUCCESS else None


def _int_property(getter: Any, handle: Any, code: int) -> int | None:
    value = _bytes(getter, handle, code)
    return int.from_bytes(value, byteorder=sys.byteorder, signed=False) if value else None


def _device_type(value: int | None) -> list[str]:
    labels = ((1, "default"), (2, "cpu"), (4, "gpu"), (8, "accelerator"), (16, "custom"))
    return [name for bit, name in labels if value and value & bit]


def _split_extensions(value: str | None) -> list[str]:
    return sorted(value.split()) if value else []


def _split_builtins(value: str | None) -> list[str]:
    return [item.strip() for item in value.split(";") if item.strip()] if value else []


def _flags(value: int | None, definitions: dict[str, int]) -> list[str] | None:
    """Decode a bit field without treating an unsupported query as no flags."""
    return [name for name, bit in definitions.items() if value & bit] if value is not None else None


def _bool(value: int | None) -> bool | None:
    """Preserve an unavailable OpenCL property as unknown rather than false."""
    return None if value is None else bool(value)


def _opencl_api() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe = {"available": False, "library": None, "status": "OpenCL loader was not found", "platform_count": 0}
    library, name = _load_opencl()
    probe["library"] = name
    if library is None:
        return probe, []
    try:
        library.clGetPlatformIDs.argtypes = [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)]
        library.clGetPlatformIDs.restype = ctypes.c_int
        library.clGetPlatformInfo.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        library.clGetPlatformInfo.restype = ctypes.c_int
        library.clGetDeviceIDs.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint)]
        library.clGetDeviceIDs.restype = ctypes.c_int
        library.clGetDeviceInfo.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)]
        library.clGetDeviceInfo.restype = ctypes.c_int
        count = ctypes.c_uint()
        result = library.clGetPlatformIDs(0, None, ctypes.byref(count))
        if result != CL_SUCCESS:
            probe["status"] = "no OpenCL platforms reported by installed loader" if result == CL_PLATFORM_NOT_FOUND_KHR else f"clGetPlatformIDs failed with OpenCL result {result}"
            return probe, []
        platforms_raw = (ctypes.c_void_p * count.value)()
        if library.clGetPlatformIDs(count.value, platforms_raw, None) != CL_SUCCESS:
            probe["status"] = "OpenCL platform enumeration failed"
            return probe, []
        platforms: list[dict[str, Any]] = []
        for platform_id in platforms_raw:
            platform_data = {label: _string(library.clGetPlatformInfo, platform_id, code) for label, code in PLATFORM_INFO.items()}
            platform_data["extensions"] = _split_extensions(platform_data["extensions"])
            device_count = ctypes.c_uint()
            device_result = library.clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_ALL, 0, None, ctypes.byref(device_count))
            devices: list[dict[str, Any]] = []
            if device_result == CL_SUCCESS and device_count.value:
                device_ids = (ctypes.c_void_p * device_count.value)()
                if library.clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_ALL, device_count.value, device_ids, None) == CL_SUCCESS:
                    devices = [_collect_device(library.clGetDeviceInfo, device_id) for device_id in device_ids]
            platform_data["device_query_result"] = device_result
            platform_data["devices"] = devices
            platforms.append(platform_data)
        probe.update({"available": True, "status": "available", "platform_count": len(platforms)})
        return probe, platforms
    except (AttributeError, OSError, ValueError) as error:
        probe["status"] = f"OpenCL API probe failed: {type(error).__name__}"
        return probe, []


def _collect_device(getter: Any, device_id: Any) -> dict[str, Any]:
    strings = {label: _string(getter, device_id, code) for label, code in STRING_PROPERTIES.items()}
    raw_type = _int_property(getter, device_id, 0x1000)
    numeric = {label: _int_property(getter, device_id, code) for label, code in UINT_PROPERTIES.items()}
    numeric.update({label: _int_property(getter, device_id, code) for label, code in SIZE_PROPERTIES.items()})
    numeric.update({label: _int_property(getter, device_id, code) for label, code in ULONG_PROPERTIES.items()})
    dimensions = numeric.get("max_work_item_dimensions")
    work_sizes = _bytes(getter, device_id, 0x1005)
    size_width = ctypes.sizeof(ctypes.c_size_t)
    result: dict[str, Any] = {
        "name": strings["name"], "vendor": strings["vendor"], "device_type": _device_type(raw_type),
        "profile": strings["profile"], "device_version": strings["device_version"], "driver_version": strings["driver_version"],
        "opencl_c_version": strings["opencl_c_version"], "il_version": strings["il_version"],
        "extensions": _split_extensions(strings["extensions"]), "built_in_kernels": _split_builtins(strings["built_in_kernels"]),
        "limits": numeric,
        "max_work_item_sizes": [int.from_bytes(work_sizes[index:index + size_width], sys.byteorder) for index in range(0, min(len(work_sizes or b""), (dimensions or 0) * size_width), size_width)] if work_sizes else [],
    }
    # These bit fields are more useful to LLM consumers decoded than as opaque numbers.
    result["features"] = {
        "image_support": _bool(_int_property(getter, device_id, 0x1016)),
        "compiler_available": _bool(numeric.get("compiler_available")),
        "linker_available": _bool(_int_property(getter, device_id, 0x103E)),
        "error_correction": _bool(numeric.get("error_correction_support")),
        "svm_capabilities": numeric.get("svm_capabilities"),
        "svm_features": _flags(numeric.get("svm_capabilities"), {"coarse_grain_buffer": 1, "fine_grain_buffer": 2, "fine_grain_system": 4, "atomics": 8}),
        "execution_capabilities": numeric.get("execution_capabilities"),
        "execution_features": _flags(numeric.get("execution_capabilities"), {"kernel": 1, "native_kernel": 2}),
        "queue_properties": numeric.get("queue_properties"),
        "queue_features": _flags(numeric.get("queue_properties"), {"out_of_order": 1, "profiling": 2}),
        "single_fp_config": numeric.get("single_fp_config"), "double_fp_config": numeric.get("double_fp_config"), "half_fp_config": numeric.get("half_fp_config"),
        "single_fp_features": _flags(numeric.get("single_fp_config"), {"denorm": 1, "inf_nan": 2, "round_to_nearest": 4, "round_to_zero": 8, "round_to_inf": 16, "fma": 32, "soft_float": 64, "correctly_rounded_divide_sqrt": 128}),
        "double_fp_features": _flags(numeric.get("double_fp_config"), {"denorm": 1, "inf_nan": 2, "round_to_nearest": 4, "round_to_zero": 8, "round_to_inf": 16, "fma": 32, "soft_float": 64, "correctly_rounded_divide_sqrt": 128}),
        "half_fp_features": _flags(numeric.get("half_fp_config"), {"denorm": 1, "inf_nan": 2, "round_to_nearest": 4, "round_to_zero": 8, "round_to_inf": 16, "fma": 32}),
    }
    return result


def _linux_icds() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for directory in (Path("/etc/OpenCL/vendors"), Path("/usr/share/OpenCL/vendors")):
        if directory.is_dir():
            for item in sorted(directory.glob("*.icd")):
                try:
                    library = item.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    library = None
                entries.append({"manifest": str(item), "library": library or None})
    return entries


def _windows_icds() -> list[dict[str, Any]]:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Khronos\OpenCL\Vendors")
        values: list[dict[str, Any]] = []
        index = 0
        while True:
            try:
                name, enabled, _ = winreg.EnumValue(key, index)
                values.append({"library": name, "enabled": enabled == 0})
                index += 1
            except OSError:
                break
        return values
    except (ImportError, OSError):
        return []


def _clinfo() -> dict[str, Any]:
    path = shutil.which("clinfo")
    probe: dict[str, Any] = {"available": False, "path": path, "status": "clinfo was not found", "json": None, "json_supported": False, "list_output": [], "list_output_truncated": False}
    if not path:
        return probe
    listing, list_status = _run(path, "-l")
    structured, structured_status = _run(path, "--json")
    parsed = None
    if structured_status == 0 and structured:
        try:
            parsed = json.loads(structured)
        except json.JSONDecodeError:
            pass
    lines = listing.splitlines() if list_status == 0 and listing else []
    probe.update({"available": bool(list_status == 0 or structured_status == 0), "status": "available" if list_status == 0 or structured_status == 0 else "clinfo failed", "list_output": lines[:40], "list_output_truncated": len(lines) > 40, "json": parsed, "json_supported": parsed is not None})
    return probe


def collect_opencl_info() -> dict[str, Any]:
    api, platforms = _opencl_api()
    icds = _windows_icds() if sys.platform == "win32" else (_linux_icds() if sys.platform.startswith("linux") else [])
    clinfo = _clinfo()
    return {
        "schema_version": 1,
        "platform": {"operating_system": platform.system(), "operating_system_release": platform.release(), "machine": platform.machine()},
        "availability": {"opencl_api": api["available"], "clinfo": clinfo["available"], "detected": bool(api["available"] or clinfo["available"])},
        "probes": {"opencl_api": api, "clinfo": clinfo},
        "installations": {"loader_library": api.get("library"), "icd_manifests": icds, "environment": {name: os.environ.get(name) for name in ("OCL_ICD_VENDORS", "OPENCL_VENDOR_PATH") if os.environ.get(name)}},
        "platforms": platforms,
    }


def _human(report: dict[str, Any]) -> None:
    print("OpenCL: " + ("detected" if report["availability"]["detected"] else "not detected"))
    print("Loader API: %s | clinfo: %s | platforms: %s" % (report["availability"]["opencl_api"], report["availability"]["clinfo"], len(report["platforms"])))
    for index, item in enumerate(report["platforms"]):
        print("Platform %d: %s (%s), OpenCL %s, %d device(s), %d extension(s)" % (index, item.get("name") or "unknown", item.get("vendor") or "unknown", item.get("version") or "unknown", len(item["devices"]), len(item["extensions"])))
        for device in item["devices"]:
            limits = device["limits"]
            print("  %s [%s]: %s CU, %s MiB global memory, %d extension(s)" % (device.get("name") or "unknown", "/".join(device["device_type"]) or "unknown", limits.get("max_compute_units", "unknown"), (limits["global_mem_size_bytes"] // (1024 * 1024) if limits.get("global_mem_size_bytes") else "unknown"), len(device["extensions"])))
    if not report["platforms"]:
        print("No OpenCL platforms were enumerated. See --json probes for the reason.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Report OpenCL platforms, devices, ICD configuration, extensions, and limits.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_opencl_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
