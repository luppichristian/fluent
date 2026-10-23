#!/usr/bin/env python3
# description: Cross-platform NVIDIA GPU and graphics-feature evidence inspector.
"""Inspect NVIDIA GPUs without treating a product name as a capability test.

The NVIDIA driver APIs expose CUDA device identity and NVENC/NVDEC capacity,
but they do not provide a general "does this game support DLSS" switch.  This
tool therefore reports the evidence behind each result and keeps detected,
supported, and architecture-only eligibility separate.
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
import tempfile
from pathlib import Path
from typing import Any


NVIDIA_PCI_VENDOR_ID = 0x10DE
_NVIDIA_SMI_FIELDS = "index,name,uuid,pci.bus_id,driver_version"


class _NvmlPciInfo(ctypes.Structure):
    """NVML's v2/v3-compatible PCI structure (the trailing busId is v2+)."""
    _fields_ = [
        ("busIdLegacy", ctypes.c_char * 16), ("domain", ctypes.c_uint),
        ("bus", ctypes.c_uint), ("device", ctypes.c_uint),
        ("pciDeviceId", ctypes.c_uint), ("pciSubSystemId", ctypes.c_uint),
        ("busId", ctypes.c_char * 32),
    ]


def _run(*command: str, timeout: int = 20) -> tuple[str | None, str | None]:
    """Run an optional read-only probe and retain a concise failure reason."""
    if not command or not command[0] or not shutil.which(command[0]):
        return None, "not_found"
    try:
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, "timed_out"
    except OSError as error:
        return None, type(error).__name__
    if completed.returncode:
        return None, "exit_%d" % completed.returncode
    return completed.stdout, None


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _version(raw: int | None) -> str | None:
    if raw is None:
        return None
    return "%d.%d" % (raw // 1000, (raw % 1000) // 10) if raw >= 1000 else str(raw)


def _clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _clean(item) for key, item in value.items() if item not in (None, "")}
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


def _load_cuda() -> tuple[Any | None, str | None]:
    names = ["nvcuda.dll"] if sys.platform == "win32" else ["libcuda.so.1", "libcuda.so"]
    located = ctypes.util.find_library("cuda")
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == "win32" else ctypes.CDLL
    for name in dict.fromkeys(names):
        try:
            return loader(name), name
        except OSError:
            pass
    return None, None


def _cuda_driver() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe: dict[str, Any] = {"available": False, "library": None, "status": "CUDA Driver API library was not found", "driver_version": None}
    library, library_name = _load_cuda()
    probe["library"] = library_name
    if library is None:
        return probe, []
    try:
        library.cuInit.argtypes, library.cuInit.restype = [ctypes.c_uint], ctypes.c_int
        result = library.cuInit(0)
        if result != 0:
            probe["status"] = "cuInit failed with CUDA result %d" % result
            return probe, []
        library.cuDriverGetVersion.argtypes, library.cuDriverGetVersion.restype = [ctypes.POINTER(ctypes.c_int)], ctypes.c_int
        raw_version = ctypes.c_int()
        if library.cuDriverGetVersion(ctypes.byref(raw_version)) == 0:
            probe["driver_version"] = _version(raw_version.value)
            probe["driver_version_raw"] = raw_version.value
        library.cuDeviceGetCount.argtypes, library.cuDeviceGetCount.restype = [ctypes.POINTER(ctypes.c_int)], ctypes.c_int
        count = ctypes.c_int()
        if library.cuDeviceGetCount(ctypes.byref(count)) != 0:
            probe["status"] = "CUDA driver initialized but device enumeration failed"
            return probe, []
        library.cuDeviceGet.argtypes, library.cuDeviceGet.restype = [ctypes.POINTER(ctypes.c_int), ctypes.c_int], ctypes.c_int
        library.cuDeviceGetName.argtypes, library.cuDeviceGetName.restype = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int], ctypes.c_int
        library.cuDeviceComputeCapability.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        library.cuDeviceComputeCapability.restype = ctypes.c_int
        get_uuid = getattr(library, "cuDeviceGetUuid_v2", None) or getattr(library, "cuDeviceGetUuid", None)
        if get_uuid:
            get_uuid.argtypes, get_uuid.restype = [ctypes.c_void_p, ctypes.c_int], ctypes.c_int
        get_pci_bus_id = getattr(library, "cuDeviceGetPCIBusId", None)
        if get_pci_bus_id:
            get_pci_bus_id.argtypes, get_pci_bus_id.restype = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int], ctypes.c_int
        devices: list[dict[str, Any]] = []
        for index in range(count.value):
            device, major, minor = ctypes.c_int(), ctypes.c_int(), ctypes.c_int()
            if library.cuDeviceGet(ctypes.byref(device), index) != 0:
                continue
            name = ctypes.create_string_buffer(256)
            library.cuDeviceGetName(name, len(name), device.value)
            capability = None
            if library.cuDeviceComputeCapability(ctypes.byref(major), ctypes.byref(minor), device.value) == 0:
                capability = "%d.%d" % (major.value, minor.value)
            uuid = None
            if get_uuid:
                uuid_bytes = (ctypes.c_ubyte * 16)()
                if get_uuid(ctypes.byref(uuid_bytes), device.value) == 0:
                    raw_uuid = bytes(uuid_bytes).hex()
                    uuid = "GPU-%s-%s-%s-%s-%s" % (raw_uuid[:8], raw_uuid[8:12], raw_uuid[12:16], raw_uuid[16:20], raw_uuid[20:])
            pci_bus_id = None
            if get_pci_bus_id:
                pci = ctypes.create_string_buffer(32)
                if get_pci_bus_id(pci, len(pci), device.value) == 0:
                    pci_bus_id = pci.value.decode(errors="replace") or None
            devices.append({"index": index, "name": name.value.decode(errors="replace") or None, "compute_capability": capability, "uuid": uuid, "pci_bus_id": pci_bus_id})
        probe.update({"available": True, "status": "available", "device_count": len(devices)})
        return probe, devices
    except (AttributeError, OSError, ValueError) as error:
        probe["status"] = "CUDA Driver API probe failed: %s" % type(error).__name__
        return probe, []


def _nvidia_smi() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = shutil.which("nvidia-smi")
    probe: dict[str, Any] = {"available": False, "path": path, "status": "nvidia-smi was not found", "driver_version": None}
    if not path:
        return probe, []
    output, error = _run(path, "--query-gpu=" + _NVIDIA_SMI_FIELDS, "--format=csv,noheader,nounits")
    header, _ = _run(path)
    if header:
        match = re.search(r"(?:Driver|KMD) Version:\s*([^\s]+)", header)
        probe["driver_version"] = match.group(1) if match else None
    if output is None:
        probe["status"] = "nvidia-smi query failed: %s" % error
        return probe, []
    fields = _NVIDIA_SMI_FIELDS.split(",")
    devices: list[dict[str, Any]] = []
    for row in output.splitlines():
        values = [value.strip() for value in row.split(",")]
        if len(values) != len(fields):
            continue
        item = dict(zip(fields, values))
        devices.append({"index": _int(item["index"]), "name": item["name"] or None, "uuid": item["uuid"] or None, "pci_bus_id": item["pci.bus_id"] or None, "driver_version": item["driver_version"] or None})
    probe.update({"available": True, "status": "available", "device_count": len(devices)})
    return probe, devices


def _load_nvml() -> tuple[Any | None, str | None]:
    names = ["nvml.dll"] if sys.platform == "win32" else ["libnvidia-ml.so.1", "libnvidia-ml.so"]
    located = ctypes.util.find_library("nvidia-ml")
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == "win32" else ctypes.CDLL
    for name in dict.fromkeys(names):
        try:
            return loader(name), name
        except OSError:
            pass
    return None, None


def _nvml() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Use NVML capacity APIs, rather than guessing codec support from a SKU."""
    probe: dict[str, Any] = {"available": False, "library": None, "status": "NVML library was not found", "driver_version": None}
    library, library_name = _load_nvml()
    probe["library"] = library_name
    if library is None:
        return probe, {}
    try:
        initialize = getattr(library, "nvmlInit_v2", None) or library.nvmlInit
        initialize.restype = ctypes.c_int
        result = initialize()
        if result != 0:
            probe["status"] = "NVML initialization failed with result %d" % result
            return probe, {}
        try:
            driver = ctypes.create_string_buffer(80)
            get_driver = getattr(library, "nvmlSystemGetDriverVersion")
            get_driver.argtypes, get_driver.restype = [ctypes.c_char_p, ctypes.c_uint], ctypes.c_int
            if get_driver(driver, len(driver)) == 0:
                probe["driver_version"] = driver.value.decode(errors="replace")
            count = ctypes.c_uint()
            get_count = getattr(library, "nvmlDeviceGetCount_v2", None) or library.nvmlDeviceGetCount
            get_count.argtypes, get_count.restype = [ctypes.POINTER(ctypes.c_uint)], ctypes.c_int
            if get_count(ctypes.byref(count)) != 0:
                probe["status"] = "NVML initialized but device enumeration failed"
                return probe, {}
            get_handle = getattr(library, "nvmlDeviceGetHandleByIndex_v2", None) or library.nvmlDeviceGetHandleByIndex
            get_handle.argtypes, get_handle.restype = [ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int
            get_uuid = getattr(library, "nvmlDeviceGetUUID", None)
            if get_uuid:
                get_uuid.argtypes, get_uuid.restype = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint], ctypes.c_int
            get_name = getattr(library, "nvmlDeviceGetName", None)
            if get_name:
                get_name.argtypes, get_name.restype = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint], ctypes.c_int
            get_pci = getattr(library, "nvmlDeviceGetPciInfo_v3", None) or getattr(library, "nvmlDeviceGetPciInfo_v2", None)
            if get_pci:
                get_pci.argtypes, get_pci.restype = [ctypes.c_void_p, ctypes.POINTER(_NvmlPciInfo)], ctypes.c_int
            devices: list[dict[str, Any]] = []
            for index in range(count.value):
                handle = ctypes.c_void_p()
                if get_handle(index, ctypes.byref(handle)) != 0:
                    continue
                decoder = _codec_capacities(library, "nvmlDeviceGetDecoderCapacity", handle)
                decoder["utilization"] = _decoder_utilization(library, handle)
                uuid_buffer, name_buffer = ctypes.create_string_buffer(96), ctypes.create_string_buffer(96)
                uuid = uuid_buffer.value.decode(errors="replace") if get_uuid and get_uuid(handle, uuid_buffer, len(uuid_buffer)) == 0 else None
                name = name_buffer.value.decode(errors="replace") if get_name and get_name(handle, name_buffer, len(name_buffer)) == 0 else None
                pci_info = _NvmlPciInfo()
                pci_bus_id = pci_info.busId.split(b"\0", 1)[0].decode(errors="replace") if get_pci and get_pci(handle, ctypes.byref(pci_info)) == 0 else None
                devices.append({"index": index, "uuid": uuid, "pci_bus_id": pci_bus_id, "name": name, "codec_capabilities": {"nvenc": _codec_capacities(library, "nvmlDeviceGetEncoderCapacity", handle), "nvdec": decoder}})
            probe.update({"available": True, "status": "available", "device_count": count.value})
            return probe, devices
        finally:
            shutdown = getattr(library, "nvmlShutdown", None)
            if shutdown:
                shutdown()
    except (AttributeError, OSError, ValueError) as error:
        probe["status"] = "NVML probe failed: %s" % type(error).__name__
        return probe, {}


def _codec_capacities(library: Any, function_name: str, handle: ctypes.c_void_p) -> dict[str, Any]:
    function = getattr(library, function_name, None)
    if function is None:
        return {"api_available": False, "status": "capacity_api_not_exported", "codecs": {}}
    function.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
    function.restype = ctypes.c_int
    # Values are the public NVML enum order for H.264, HEVC, and AV1.  An
    # invalid enum on an older driver remains evidence of an older API, not of
    # an unsupported hardware codec.
    codecs: dict[str, Any] = {}
    for name, query_type in (("h264", 0), ("hevc", 1), ("av1", 2)):
        capacity = ctypes.c_uint()
        result = function(handle, query_type, ctypes.byref(capacity))
        codecs[name] = {"nvml_result": result, "capacity_percent": capacity.value if result == 0 else None}
    successes = [item for item in codecs.values() if item["nvml_result"] == 0]
    return {"api_available": True, "status": "available" if successes else "no_successful_codec_query", "codecs": codecs}


def _decoder_utilization(library: Any, handle: ctypes.c_void_p) -> dict[str, Any]:
    """NVML exposes this more widely than decoder codec-capacity queries."""
    function = getattr(library, "nvmlDeviceGetDecoderUtilization", None)
    if function is None:
        return {"api_available": False, "status": "utilization_api_not_exported"}
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    function.restype = ctypes.c_int
    utilization, period = ctypes.c_uint(), ctypes.c_uint()
    result = function(handle, ctypes.byref(utilization), ctypes.byref(period))
    return {"api_available": True, "nvml_result": result, "utilization_percent": utilization.value if result == 0 else None, "sampling_period_microseconds": period.value if result == 0 else None}


def _os_inventory() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    system = platform.system()
    if system == "Windows":
        command = r"Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,DriverVersion,PNPDeviceID | ConvertTo-Json -Compress"
        raw, error = _run(shutil.which("powershell") or shutil.which("pwsh") or "", "-NoProfile", "-NonInteractive", "-Command", command)
        try:
            rows = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            rows = []
        rows = rows if isinstance(rows, list) else [rows] if isinstance(rows, dict) else []
        devices = [{"name": row.get("Name"), "driver_version": row.get("DriverVersion"), "pnp_device_id": row.get("PNPDeviceID")} for row in rows if "nvidia" in (str(row.get("AdapterCompatibility")) + str(row.get("Name"))).lower()]
        return {"available": raw is not None, "source": "windows_cim", "status": "available" if raw is not None else error}, devices
    if system == "Linux":
        raw, error = _run("lspci", "-mm", "-nn")
        devices = []
        for line in (raw or "").splitlines():
            if "nvidia" in line.lower() or "[10de:" in line.lower():
                devices.append({"name": line, "pci_record": line})
        return {"available": raw is not None, "source": "lspci", "status": "available" if raw is not None else error}, devices
    return {"available": False, "source": None, "status": "no_supported_os_fallback"}, []


def _collect_vk_extensions(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            # Extensions occur as map keys in Vulkan Profiles reports or as
            # an `extensionName` value in older vulkaninfo schemas. Do not
            # treat arbitrary feature enum strings as extensions.
            if isinstance(key, str) and key.startswith("VK_"):
                found.add(key)
            if isinstance(key, str) and "extensionname" in key.lower() and isinstance(item, str) and item.startswith("VK_"):
                found.add(item)
            found.update(_collect_vk_extensions(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_collect_vk_extensions(item))
    return found


def _vulkan() -> dict[str, Any]:
    executable = shutil.which("vulkaninfo")
    probe: dict[str, Any] = {"available": False, "path": executable, "status": "vulkaninfo was not found", "nvidia_device_extensions": {}}
    if not executable:
        return probe
    # SDK releases vary: some write a Vulkan Profiles JSON file instead of
    # stdout. A private temporary directory handles both without changing the
    # caller's working tree.
    try:
        with tempfile.TemporaryDirectory(prefix="nvidia-info-") as directory:
            completed = subprocess.run([executable, "--json"], cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            if completed.returncode != 0:
                probe["status"] = "vulkaninfo --json failed: exit_%d" % completed.returncode
                return probe
            generated = list(Path(directory).glob("VP_VULKANINFO_*.json"))
            if generated:
                raw = generated[0].read_text(encoding="utf-8", errors="replace")
            else:
                raw = completed.stdout
            if not raw.strip():
                probe["status"] = "vulkaninfo --json emitted no report"
                return probe
            document = json.loads(raw)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        probe["status"] = "vulkaninfo JSON probe failed: %s" % type(error).__name__
        return probe

    scopes: list[dict[str, Any]] = []
    def visit(item: Any) -> None:
        if isinstance(item, dict):
            vendor = next((_int(item.get(key)) for key in ("vendorID", "vendorId", "vendor_id") if _int(item.get(key)) is not None), None)
            name = next((item.get(key) for key in ("deviceName", "device_name") if item.get(key)), None)
            if vendor == NVIDIA_PCI_VENDOR_ID:
                extensions = _collect_vk_extensions(item)
                if extensions:
                    scopes.append({"name": name, "extensions": sorted(extensions)})
                return
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(document)
    # Vulkan Profiles JSON represents a chosen physical device as one
    # `capabilities.device` tree. In that schema the vendor property and the
    # extensions map are siblings, so a generic nested-device walk cannot
    # associate them. Preserve the association only when this explicit schema
    # gives us both pieces of evidence.
    profile_device = document.get("capabilities", {}).get("device", {}) if isinstance(document, dict) else {}
    profile_extensions = set((profile_device.get("extensions") or {}).keys()) if isinstance(profile_device, dict) else set()
    properties = profile_device.get("properties", {}) if isinstance(profile_device, dict) else {}
    core_properties = properties.get("VkPhysicalDeviceProperties", {}) if isinstance(properties, dict) else {}
    profile_vendor = _int(core_properties.get("vendorID")) if isinstance(core_properties, dict) else None
    if profile_vendor == NVIDIA_PCI_VENDOR_ID and profile_extensions:
        scopes.append({"name": core_properties.get("deviceName"), "extensions": sorted(profile_extensions)})
    # Per-device scope is deliberately required.  A global Vulkan extension
    # list may describe a different vendor on multi-GPU computers.
    probe.update({"available": True, "status": "available", "nvidia_device_extensions": {str(index): scope for index, scope in enumerate(scopes)}})
    if not scopes:
        probe["status"] = "available; JSON schema did not expose a scoped NVIDIA physical-device record"
    return probe


def _ngx_components() -> dict[str, Any]:
    names = {"dlss_super_resolution": ("nvngx_dlss.dll", "libnvidia-ngx-dlss.so", "libnvidia-ngx-dlss.so.1"), "dlss_frame_generation": ("nvngx_dlssg.dll", "libnvidia-ngx-dlssg.so", "libnvidia-ngx-dlssg.so.1"), "dlss_ray_reconstruction": ("nvngx_dlssd.dll", "libnvidia-ngx-dlssd.so", "libnvidia-ngx-dlssd.so.1")}
    roots = [Path(path) for path in os.environ.get("PATH", "").split(os.pathsep) if path]
    if sys.platform == "win32":
        roots.append(Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32")
    found: dict[str, list[str]] = {}
    for feature, candidates in names.items():
        found[feature] = [str(root / candidate) for root in roots for candidate in candidates if (root / candidate).is_file()]
    return {"searched_paths": len(roots), "components": found}


def _feature(detection: str = "unknown", support: str = "unknown", eligibility: str = "unknown", evidence: list[dict[str, Any]] | None = None, limitation: str | None = None) -> dict[str, Any]:
    result = {"detection": detection, "support": support, "eligibility": eligibility, "evidence": evidence or []}
    if limitation:
        result["limitations"] = [limitation]
    return result


def _cc_number(device: dict[str, Any]) -> float | None:
    try:
        return float(str(device.get("compute_capability")))
    except (TypeError, ValueError):
        return None


def _capabilities(device: dict[str, Any], nvml: dict[str, Any], vulkan_extensions: set[str], ngx: dict[str, Any]) -> dict[str, Any]:
    cc = _cc_number(device)
    compute_evidence = [{"source": "cuda_driver_api", "fact": "compute_capability", "value": device.get("compute_capability")}] if cc is not None else []
    caps: dict[str, Any] = {}
    for feature in ("dlss_super_resolution", "dlss_frame_generation", "dlss_ray_reconstruction"):
        files = ngx["components"].get(feature, [])
        caps[feature] = _feature("detected" if files else "unknown", "unknown", "unknown", [{"source": "local_ngx_component", "paths": files}] if files else [], "DLSS support is negotiated by NGX in an application; neither a GPU name nor a driver version confirms it.")
    reflex_extensions = {"VK_NV_low_latency", "VK_NV_low_latency2"}
    reflex = sorted(vulkan_extensions & reflex_extensions)
    caps["reflex"] = _feature("detected" if reflex else "unknown", "unknown", "unknown", [{"source": "vulkaninfo", "extensions": reflex}] if reflex else [], "A Vulkan low-latency extension is evidence of a driver interface, not proof that NVIDIA Reflex SDK integration will initialize in a game.")
    ray_extensions = {"VK_KHR_acceleration_structure", "VK_KHR_ray_tracing_pipeline"}
    ray = sorted(vulkan_extensions & ray_extensions)
    caps["rtx_ray_tracing"] = _feature("detected" if len(ray) == len(ray_extensions) else "unknown", "supported" if len(ray) == len(ray_extensions) else "unknown", "unknown", [{"source": "vulkaninfo", "extensions": ray}] if ray else [], "Requires both Vulkan ray-tracing extensions in a NVIDIA physical-device scope; CUDA compute capability alone does not prove RT-core availability.")
    tensor_eligible = cc is not None and cc >= 7.0
    caps["tensor_cores"] = _feature("unknown", "unknown", "likely_eligible_by_architecture" if tensor_eligible else "unknown", compute_evidence, "CUDA reports compute capability, not a direct Tensor Core feature bit. Eligibility is not a workload or library support test.")
    for feature in ("nvenc", "nvdec"):
        capacity = nvml.get(feature) or {"api_available": False, "status": "not_queried", "codecs": {}}
        successful = [name for name, result in capacity.get("codecs", {}).items() if result.get("nvml_result") == 0]
        unsupported = [result for result in capacity.get("codecs", {}).values() if result.get("nvml_result") == 3]
        decoder_utilization = capacity.get("utilization", {}) if feature == "nvdec" else {}
        decoder_available = decoder_utilization.get("nvml_result") == 0
        support = "supported" if successful else "not_supported" if unsupported and len(unsupported) == len(capacity.get("codecs", {})) else "unknown"
        caps[feature] = _feature("detected" if successful or decoder_available else "unknown", support, "unknown", [{"source": "nvml_%s_capacity" % feature, "result": capacity}], "NVML capacity calls are direct codec-support evidence. Decoder utilization only detects a usable activity interface; it does not identify supported codecs. An unsupported or invalid codec enum on an older driver does not prove that the GPU lacks the engine.")
    return caps


def _vulkan_extensions_for(device: dict[str, Any], vulkan: dict[str, Any]) -> set[str]:
    name = str(device.get("name") or "").casefold()
    matches: set[str] = set()
    for scope in vulkan.get("nvidia_device_extensions", {}).values():
        scope_name = str(scope.get("name") or "").casefold()
        if name and scope_name and (name == scope_name or name in scope_name or scope_name in name):
            matches.update(scope.get("extensions") or [])
    return matches


def _normalized_pci_bus_id(value: Any) -> str | None:
    """Normalize NVIDIA's 00000000:01:00.0 and Vulkan-style BDF variants."""
    match = re.fullmatch(r"\s*(?:(?:[0-9a-fA-F]{1,8}):)?([0-9a-fA-F]{1,2}):([0-9a-fA-F]{1,2})\.([0-7])\s*", str(value or ""))
    if not match:
        return None
    bus, device, function = match.groups()
    return "0000:%02x:%02x.%d" % (int(bus, 16), int(device, 16), int(function))


def _find_identity_match(device: dict[str, Any], candidates: list[dict[str, Any]], used: set[int]) -> int | None:
    """Match UUID before PCI, refusing ambiguous PCI/MIG fallback matches."""
    uuid = str(device.get("uuid") or "").casefold()
    if uuid:
        matches = [index for index, candidate in enumerate(candidates) if index not in used and str(candidate.get("uuid") or "").casefold() == uuid]
        if len(matches) == 1:
            return matches[0]
        # A CUDA MIG UUID intentionally does not borrow the parent GPU's
        # encoder/decoder result through PCI. Preserve both records instead.
        return None
    pci = _normalized_pci_bus_id(device.get("pci_bus_id"))
    if pci:
        matches = [index for index, candidate in enumerate(candidates) if index not in used and _normalized_pci_bus_id(candidate.get("pci_bus_id")) == pci]
        if len(matches) == 1:
            return matches[0]
    return None


def _merge_devices(cuda: list[dict[str, Any]], smi: list[dict[str, Any]], os_devices: list[dict[str, Any]], nvml: list[dict[str, Any]], vulkan: dict[str, Any], ngx: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge physical-device sources without assuming their ordinals agree.

    CUDA_VISIBLE_DEVICES, CUDA_DEVICE_ORDER, and MIG can make CUDA ordinal 0
    correspond to a different physical GPU (or compute instance) than ordinal
    0 in NVML/nvidia-smi. UUID is authoritative; PCI is only accepted when it
    identifies exactly one otherwise-unmatched record.
    """
    devices: list[dict[str, Any]] = []
    used_smi: set[int] = set()
    for item in cuda:
        smi_index = _find_identity_match(item, smi, used_smi)
        smi_item = smi[smi_index] if smi_index is not None else {}
        if smi_index is not None:
            used_smi.add(smi_index)
        devices.append({"index": item.get("index"), "name": item.get("name") or smi_item.get("name"), "compute_capability": item.get("compute_capability"), "uuid": item.get("uuid") or smi_item.get("uuid"), "pci_bus_id": item.get("pci_bus_id") or smi_item.get("pci_bus_id"), "driver_version": smi_item.get("driver_version"), "sources": ["cuda_driver_api"] + (["nvidia_smi"] if smi_index is not None else [])})
    for index, item in enumerate(smi):
        if index not in used_smi:
            devices.append({"index": item.get("index"), "name": item.get("name"), "uuid": item.get("uuid"), "pci_bus_id": item.get("pci_bus_id"), "driver_version": item.get("driver_version"), "sources": ["nvidia_smi"]})

    used_nvml: set[int] = set()
    for device in devices:
        nvml_index = _find_identity_match(device, nvml, used_nvml)
        if nvml_index is not None:
            used_nvml.add(nvml_index)
            device["nvml_capabilities"] = nvml[nvml_index].get("codec_capabilities", {})
            device["sources"].append("nvml")
    # Preserve an NVML-only device rather than borrowing an ordinal from a
    # CUDA-visible set. This is especially important with MIG instances.
    for index, item in enumerate(nvml):
        if index not in used_nvml:
            devices.append({"index": None, "name": item.get("name"), "uuid": item.get("uuid"), "sources": ["nvml"], "nvml_capabilities": item.get("codec_capabilities", {})})

    # OS inventory is a fallback, so retain it rather than merging by model
    # name (identical GPUs make that match unreliable).
    if not devices:
        for item in os_devices:
            devices.append({"index": None, "name": item.get("name"), "driver_version": item.get("driver_version"), "sources": ["os_inventory"], "os_evidence": item})
    for device in devices:
        device["capabilities"] = _capabilities(device, device.pop("nvml_capabilities", {}), _vulkan_extensions_for(device, vulkan), ngx)
    return [_clean(device) for device in devices]


def collect_nvidia_info() -> dict[str, Any]:
    cuda_probe, cuda_devices = _cuda_driver()
    smi_probe, smi_devices = _nvidia_smi()
    nvml_probe, nvml_devices = _nvml()
    os_probe, os_devices = _os_inventory()
    vulkan_probe = _vulkan()
    ngx_probe = _ngx_components()
    devices = _merge_devices(cuda_devices, smi_devices, os_devices, nvml_devices, vulkan_probe, ngx_probe)
    return {
        "schema_version": 1,
        "platform": {"operating_system": platform.system(), "operating_system_release": platform.release(), "machine": platform.machine()},
        "availability": {"nvidia_devices_detected": bool(devices), "cuda_driver_api": cuda_probe["available"], "nvidia_smi": smi_probe["available"], "nvml": nvml_probe["available"], "vulkaninfo": vulkan_probe["available"]},
        "driver": {"cuda_driver_version": cuda_probe.get("driver_version"), "nvidia_smi_driver_version": smi_probe.get("driver_version"), "nvml_driver_version": nvml_probe.get("driver_version")},
        "probes": {"cuda_driver_api": cuda_probe, "nvidia_smi": smi_probe, "nvml": nvml_probe, "os_inventory": os_probe, "vulkan": vulkan_probe, "ngx_components": ngx_probe},
        "devices": devices,
        "limitations": ["Feature status is per enumerated device. 'detected' is direct local evidence, 'supported' means a queried API exposed the feature, and 'likely_eligible_by_architecture' is deliberately weaker than support.", "DLSS and Reflex require an application/SDK initialization path. This read-only inventory does not start a renderer, NGX, encoder, decoder, or game."],
    }


def _human(report: dict[str, Any]) -> None:
    available = report["availability"]
    print("NVIDIA GPUs: %s" % ("detected" if available["nvidia_devices_detected"] else "not detected"))
    print("CUDA Driver API: %s | NVML: %s | nvidia-smi: %s | Vulkan probe: %s" % (available["cuda_driver_api"], available["nvml"], available["nvidia_smi"], available["vulkaninfo"]))
    for device in report["devices"]:
        print("GPU %s: %s | compute capability %s | sources: %s" % (device.get("index", "OS"), device.get("name", "unknown"), device.get("compute_capability", "unknown"), ", ".join(device.get("sources", []))))
        for feature, result in device.get("capabilities", {}).items():
            print("  %s: detection=%s, support=%s, eligibility=%s" % (feature, result["detection"], result["support"], result["eligibility"]))
    if not report["devices"]:
        print("No NVIDIA device was enumerated. Use --json to inspect every probe result.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Report evidence-backed NVIDIA GPU, DLSS, Reflex, RTX, Tensor, NVENC, and NVDEC capability information.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_nvidia_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
