#!/usr/bin/env python3
# description: Best-effort AMD GPU, driver, API, media, and compute capability inspector.
"""Inspect AMD GPU evidence without treating product names as capabilities.

The program is deliberately conservative.  A GPU name, a PCI device ID, or
the presence of AMD Software is inventory evidence, not proof that an optional
driver setting or a game technology is enabled.  Capability records therefore
always contain a status and the evidence used to arrive at it.
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
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


AMD_PCI_VENDOR = "0x1002"


def _read(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip() or None
    except OSError:
        return None


def _run(*command: str, timeout: int = 20) -> tuple[str | None, int | None, str | None]:
    """Run an optional read-only probe and retain a compact diagnostic."""
    if not command or not shutil.which(command[0]):
        return None, None, "not installed or not on PATH"
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, check=False)
        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        return output, result.returncode, None if result.returncode == 0 else "exited with %d" % result.returncode
    except subprocess.TimeoutExpired:
        return None, None, "timed out"
    except OSError as error:
        return None, None, type(error).__name__


def _probe(command: list[str], timeout: int = 20) -> tuple[dict[str, Any], str | None]:
    path = shutil.which(command[0])
    base: dict[str, Any] = {"found": bool(path), "path": path, "command": command,
                            "status": "not installed" if not path else "not run", "exit_code": None}
    if not path:
        return base, None
    output, code, error = _run(*command, timeout=timeout)
    base.update({"status": "ok" if code == 0 else "unavailable", "exit_code": code, "error": error})
    return base, output


def _integer(value: Any) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _compact(item) for key, item in value.items() if item not in (None, "")}
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


def _is_amd_record(record: dict[str, Any]) -> bool:
    identity = " ".join(str(record.get(key) or "") for key in
                        ("pnp_device_id", "adapter_compatibility", "manufacturer", "vendor"))
    return "VEN_1002" in identity.upper() or bool(re.search(r"\b(AMD|ATI|ADVANCED MICRO DEVICES)\b", identity, re.I))


def _powershell_cim() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    command = ["powershell", "-NoProfile", "-NonInteractive", "-Command", r'''$x=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,PNPDeviceID,DriverVersion,DriverDate,DriverName,InstalledDisplayDrivers,VideoProcessor,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution); $x | ConvertTo-Json -Depth 3 -Compress''']
    probe, output = _probe(command, timeout=25)
    probe["source"] = "Win32_VideoController (CIM)"
    if not output or probe["status"] != "ok":
        return probe, []
    try:
        decoded = json.loads(output)
    except json.JSONDecodeError:
        probe.update({"status": "unavailable", "error": "CIM output was not JSON"})
        return probe, []
    rows = decoded if isinstance(decoded, list) else [decoded]
    devices: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        record = {
            "name": row.get("Name"), "adapter_compatibility": row.get("AdapterCompatibility"),
            "pnp_device_id": row.get("PNPDeviceID"), "driver_version": row.get("DriverVersion"),
            "driver_date": row.get("DriverDate"), "driver_name": row.get("DriverName"),
            "installed_display_drivers": row.get("InstalledDisplayDrivers"),
            "video_processor": row.get("VideoProcessor"), "memory_bytes": _integer(row.get("AdapterRAM")),
            "current_resolution": "%sx%s" % (row.get("CurrentHorizontalResolution"), row.get("CurrentVerticalResolution"))
            if row.get("CurrentHorizontalResolution") and row.get("CurrentVerticalResolution") else None,
        }
        if _is_amd_record(record):
            devices.append(_compact({"identity": {"vendor_id": AMD_PCI_VENDOR, "name": record["name"],
                                                  "pnp_device_id": record["pnp_device_id"]},
                                     "driver": _compact({key: record[key] for key in ("adapter_compatibility", "driver_version", "driver_date", "driver_name", "installed_display_drivers", "video_processor")}),
                                     "memory_bytes": record["memory_bytes"], "current_resolution": record["current_resolution"],
                                     "sources": ["windows_cim"]}))
    return probe, devices


def _dxdiag() -> tuple[dict[str, Any], dict[str, Any]]:
    """Read DirectX diagnostic data, if Windows supplies dxdiag.

    dxdiag has no reliable API for optional D3D extensions.  Its DDI and
    feature-level fields are preserved as API evidence only.
    """
    executable = shutil.which("dxdiag")
    if not executable and platform.system() == "Windows":
        candidate = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "dxdiag.exe"
        executable = str(candidate) if candidate.is_file() else None
    probe: dict[str, Any] = {"found": bool(executable), "path": executable, "command": ["dxdiag", "/x", "<temporary-file>"],
                             "status": "not installed" if not executable else "not run", "exit_code": None}
    details: dict[str, Any] = {"directx_version": None, "display_devices": [], "limitations": "DXDiag DDI/feature levels are not evidence of ray tracing or driver-control features."}
    if not executable:
        return probe, details
    try:
        with tempfile.TemporaryDirectory(prefix="amd-info-") as directory:
            target = Path(directory) / "dxdiag.xml"
            result = subprocess.run([executable, "/x", str(target)], text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=45, check=False)
            probe.update({"exit_code": result.returncode, "status": "ok" if result.returncode == 0 and target.is_file() else "unavailable",
                          "error": None if result.returncode == 0 and target.is_file() else "DXDiag did not create XML"})
            if probe["status"] != "ok":
                return probe, details
            root = ET.parse(target).getroot()
            details["directx_version"] = root.findtext("./SystemInformation/DirectXVersion")
            for item in root.findall(".//DisplayDevice"):
                vendor = item.findtext("Manufacturer") or ""
                device_id = item.findtext("DeviceID") or ""
                # DXDiag commonly spells this "Advanced Micro Devices, Inc."
                # rather than using the AMD abbreviation.
                if not _is_amd_record({"manufacturer": vendor, "pnp_device_id": device_id}):
                    continue
                details["display_devices"].append(_compact({"name": item.findtext("CardName"), "manufacturer": vendor,
                    "device_id": device_id, "driver_version": item.findtext("DriverVersion"),
                    "driver_date": item.findtext("DriverDate"), "ddi_version": item.findtext("DDIVersion"),
                    "feature_levels": item.findtext("FeatureLevels")}))
    except (OSError, subprocess.TimeoutExpired, ET.ParseError) as error:
        probe.update({"status": "unavailable", "error": type(error).__name__})
    return probe, details


def _linux_sysfs() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    probe: dict[str, Any] = {"found": sys.platform.startswith("linux"), "path": "/sys/class/drm", "command": None,
                             "status": "not applicable", "exit_code": None}
    devices: list[dict[str, Any]] = []
    architectures: list[dict[str, Any]] = []
    if not sys.platform.startswith("linux"):
        return probe, devices, architectures
    root = Path("/sys/class/drm")
    if not root.is_dir():
        probe.update({"status": "unavailable", "error": "DRM sysfs directory is absent"})
        return probe, devices, architectures
    for card in sorted(root.glob("card[0-9]*")):
        device = card / "device"
        if _read(device / "vendor") != AMD_PCI_VENDOR:
            continue
        driver_link = device / "driver"
        try:
            driver = driver_link.resolve().name if driver_link.exists() else None
        except OSError:
            driver = None
        devices.append(_compact({"identity": {"vendor_id": AMD_PCI_VENDOR, "pci_device_id": _read(device / "device"),
                                               "pci_revision": _read(device / "revision"), "pci_address": device.resolve().name},
                                 "driver": {"kernel_driver": driver, "module_version": _read("/sys/module/amdgpu/version")},
                                 "drm_card": card.name, "render_nodes": [node.name for node in root.glob("renderD*") if node.resolve().parent == card.resolve().parent],
                                 "sources": ["linux_sysfs"]}))
    kfd = Path("/sys/class/kfd/kfd/topology/nodes")
    for node in sorted(kfd.glob("*/properties")):
        values: dict[str, str] = {}
        for line in (_read(node) or "").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                values[parts[0]] = parts[1]
        if _integer(values.get("vendor_id")) != 0x1002:
            continue
        raw = _integer(values.get("gfx_target_version"))
        gfxip = "gfx%d" % (raw // 100) if raw else None
        architectures.append(_compact({"node": node.parent.name, "gfxip": gfxip, "gfx_target_version": raw,
                                       "source": "linux_kfd_topology", "generation": _gfx_generation(gfxip)}))
    probe.update({"status": "ok", "device_count": len(devices), "kfd_architecture_count": len(architectures)})
    return probe, devices, architectures


def _linux_lspci() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe, output = _probe(["lspci", "-Dnns"], timeout=15)
    probe["source"] = "lspci numeric PCI inventory"
    records: list[dict[str, Any]] = []
    if not output or probe["status"] != "ok":
        return probe, records
    for line in output.splitlines():
        # Example: 0000:03:00.0 0300: 1002:73bf (rev c1) ...
        match = re.match(r"^(\S+)\s+([0-9a-fA-F]{4}):\s+1002:([0-9a-fA-F]{4})(?:\s+\(rev\s+([0-9a-fA-F]+)\))?\s*(.*)$", line)
        if match and match.group(2).lower().startswith("03"):
            records.append({"pci_address": match.group(1), "class_code": "0x" + match.group(2),
                            "vendor_id": AMD_PCI_VENDOR, "pci_device_id": "0x" + match.group(3).lower(),
                            "pci_revision": "0x" + match.group(4).lower() if match.group(4) else None,
                            "description": match.group(5) or None})
    probe["amd_display_count"] = len(records)
    return probe, records


def _gfx_generation(gfxip: str | None) -> str | None:
    value = _integer((gfxip or "").replace("gfx", ""))
    if value is None:
        return None
    if value >= 1200:
        return "RDNA 4 or later"
    if value >= 1100:
        return "RDNA 3"
    if value >= 1030:
        return "RDNA 2"
    if value >= 1000:
        return "RDNA"
    if value >= 900:
        return "GCN 5 / Vega"
    return "pre-RDNA / unknown generation"


def _tool_probes() -> tuple[dict[str, Any], dict[str, str | None], list[dict[str, Any]]]:
    """Probe optional AMD diagnostics without assuming their output formats."""
    probes: dict[str, Any] = {}
    outputs: dict[str, str | None] = {}
    for key, command in {
        "rocm_smi": ["rocm-smi", "--showproductname", "--showdriverversion", "--showuniqueid"],
        "amdgpu_top": ["amdgpu_top", "--version"],
        "radeontop": ["radeontop", "--version"],
        "rocminfo": ["rocminfo"],
        "hipcc": ["hipcc", "--version"],
        "hipconfig": ["hipconfig", "--version"],
        "vainfo": ["vainfo"],
    }.items():
        timeout = 35 if key == "rocminfo" else 15
        probe, output = _probe(command, timeout=timeout)
        probes[key] = probe
        outputs[key] = output
    agents: list[dict[str, Any]] = []
    if probes["rocminfo"]["status"] == "ok":
        for match in re.finditer(r"(?im)^\s*Name:\s*(gfx[0-9a-f]+)\s*$", outputs["rocminfo"] or ""):
            gfxip = match.group(1).lower()
            agents.append({"gfxip": gfxip, "generation": _gfx_generation(gfxip), "source": "rocminfo"})
    return probes, outputs, agents


def _vulkan_value(mapping: dict[str, Any], names: set[str]) -> Any:
    """Find a field in a device object or one of its direct property maps."""
    for key, value in mapping.items():
        if key.replace("_", "").lower() in names:
            return value
    for value in mapping.values():
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.replace("_", "").lower() in names:
                    return nested
    return None


def _vulkan_vendor_id(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    try:
        return int(text, 0)
    except ValueError:
        # Some JSON emitters represent PCI IDs as a four-digit hexadecimal
        # string without the 0x prefix.
        return int(text, 16) if re.fullmatch(r"[0-9a-fA-F]{4}", text) else None


def _vulkan_extension_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.replace("_", "").lower() in {"extensionname", "extension"} and isinstance(item, str) and item.startswith("VK_"):
                names.add(item)
            names.update(_vulkan_extension_names(item))
    elif isinstance(value, list):
        for item in value:
            names.update(_vulkan_extension_names(item))
    elif isinstance(value, str) and value.startswith("VK_"):
        # Vulkan Profiles JSON has used both extensionName objects and raw
        # extension-name arrays across SDK releases.
        names.add(value)
    return names


def _amd_vulkan_devices(document: Any) -> list[dict[str, Any]]:
    """Extract extensions only from a JSON object scoped to AMD vendor ID.

    ``vulkaninfo`` JSON formats differ between SDK releases.  We intentionally
    identify device containers by a vendorID field (including a direct
    properties child), then collect extension names beneath that same container.
    A global/instance extension list is never used as AMD device evidence.
    """
    records: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            vendor = _vulkan_vendor_id(_vulkan_value(value, {"vendorid"}))
            if vendor == 0x1002:
                extensions = sorted(_vulkan_extension_names(value))
                name = _vulkan_value(value, {"devicename"})
                records.append({"vendor_id": AMD_PCI_VENDOR, "device_name": name if isinstance(name, str) else None,
                                "extensions": extensions})
                # A matched object is the narrowest vendor-scoped container
                # seen on this traversal branch; descendants would duplicate it.
                return
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(document)
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        token = json.dumps(record, sort_keys=True)
        if token not in seen:
            seen.add(token)
            unique.append(record)
    return unique


def _api_evidence() -> tuple[dict[str, Any], set[str]]:
    # Some Vulkan SDK builds create VP_VULKANINFO_*.json in their working
    # directory. Keep that implementation detail in a disposable directory.
    path = shutil.which("vulkaninfo")
    probe: dict[str, Any] = {"found": bool(path), "path": path, "command": ["vulkaninfo", "--json"],
                             "status": "not installed" if not path else "not run", "exit_code": None}
    document: Any = None
    if path:
        try:
            with tempfile.TemporaryDirectory(prefix="amd-info-vulkan-") as directory:
                result = subprocess.run([path, "--json"], cwd=directory, text=True, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=60, check=False)
                if result.returncode != 0:
                    probe.update({"status": "unavailable", "exit_code": result.returncode,
                                  "error": "exited with %d" % result.returncode})
                else:
                    reports = sorted(Path(directory).glob("VP_VULKANINFO_*.json"))
                    raw = reports[0].read_text(encoding="utf-8") if reports else result.stdout
                    try:
                        document = json.loads(raw)
                        probe.update({"status": "ok", "exit_code": result.returncode, "error": None})
                    except json.JSONDecodeError:
                        probe.update({"status": "unavailable", "exit_code": result.returncode,
                                      "error": "vulkaninfo did not emit valid JSON"})
        except subprocess.TimeoutExpired:
            probe.update({"status": "unavailable", "error": "timed out"})
        except OSError as error:
            probe.update({"status": "unavailable", "error": type(error).__name__})
    devices = _amd_vulkan_devices(document) if document is not None and probe["status"] == "ok" else []
    extensions = sorted({extension for device in devices for extension in device["extensions"]})
    selected = [item for item in extensions if item.startswith("VK_AMD_") or item in {
        "VK_KHR_acceleration_structure", "VK_KHR_ray_query", "VK_KHR_ray_tracing_pipeline",
        "VK_KHR_video_decode_queue", "VK_KHR_video_encode_queue"}]
    return {"vulkaninfo": probe, "amd_physical_devices": devices, "vulkan_extensions": selected,
            "limitations": "Only extensions beneath a vulkaninfo JSON physical-device object with vendorID 0x1002 are used as AMD evidence. Other Vulkan devices and instance extensions are excluded."}, set(extensions)


def _feature(status: str, classification: str, evidence: list[str], notes: list[str], scope: str = "unknown") -> dict[str, Any]:
    return {"status": status, "classification": classification, "scope": scope, "evidence": evidence, "notes": notes}


def _has_gfx_at_least(architectures: list[dict[str, Any]], minimum: int) -> bool:
    return any((_integer(str(item.get("gfxip") or "").replace("gfx", "")) or 0) >= minimum for item in architectures)


def _capabilities(system: str, architectures: list[dict[str, Any]], api: dict[str, Any], extension_set: set[str], tool_probes: dict[str, Any], tool_outputs: dict[str, str | None], dxdiag: dict[str, Any]) -> dict[str, Any]:
    ray_extensions = {"VK_KHR_acceleration_structure", "VK_KHR_ray_query", "VK_KHR_ray_tracing_pipeline"}
    video_extensions = {"VK_KHR_video_decode_queue", "VK_KHR_video_encode_queue"}
    va_output = tool_outputs.get("vainfo") or ""
    amd_va = bool(re.search(r"radeonsi|AMD", va_output, re.I))
    va_decode = bool(re.search(r"VAEntrypointVLD", va_output))
    va_encode = bool(re.search(r"VAEntrypointEnc", va_output))
    hip_runtime = tool_probes["rocminfo"]["status"] == "ok" and bool(architectures)
    ray_evidence = sorted(ray_extensions & extension_set)
    if ray_evidence:
        ray = _feature("detected", "graphics_api_extension", ["vulkaninfo reported " + item for item in ray_evidence],
                       ["This is Vulkan runtime evidence; inspect device association when more than one GPU is present."], "Vulkan runtime")
    elif _has_gfx_at_least(architectures, 1030):
        ray = _feature("likely_eligible_by_architecture", "architecture_inference", ["KFD/ROCm reported an RDNA 2-or-later gfx target"],
                       ["Architecture eligibility is not proof that a driver, API, or application exposes ray tracing."], "Linux AMD GPU with KFD/ROCm architecture evidence")
    else:
        ray = _feature("unknown", "hardware_and_api_feature", [], ["No AMD-correlated ray-tracing API extension or architecture evidence was observed."])
    if amd_va and (va_decode or va_encode):
        media = _feature("detected", "VA_API_media_entrypoints", ["vainfo identified an AMD/radeonsi VA driver"] +
                         (["VAEntrypointVLD (decode)"] if va_decode else []) + (["VAEntrypointEnc* (encode)"] if va_encode else []),
                         ["VA-API entrypoints describe the active Linux media driver; they do not enumerate every codec/profile or prove Windows AMF support."], "active VA-API driver")
    elif _has_gfx_at_least(architectures, 900):
        media = _feature("likely_eligible_by_architecture", "architecture_inference", ["KFD/ROCm reported a gfx9-or-later target"],
                         ["This only suggests a VCN-era media block. Exact VCN generation, codecs, and encode/decode support remain unknown without a media API report."], "Linux AMD GPU with KFD/ROCm architecture evidence")
    else:
        media = _feature("unknown", "hardware_media_feature", [], ["No AMD-correlated VA-API or architecture evidence was observed."])
    dx_devices = dxdiag.get("display_devices") or []
    dx_evidence: list[str] = []
    for device in dx_devices:
        if device.get("ddi_version"):
            dx_evidence.append("DXDiag DDI version %s" % device["ddi_version"])
        if device.get("feature_levels"):
            dx_evidence.append("DXDiag feature levels %s" % device["feature_levels"])
    direct3d = _feature("detected" if dx_evidence else "unknown", "diagnostic_API_evidence", dx_evidence,
                        ["DXDiag DDI/feature levels describe Direct3D diagnostic API evidence only. They are not an extension inventory and do not prove ray tracing or AMD Software features."],
                        "AMD DXDiag display device" if dx_evidence else "unknown")
    fsr_notes = ["FSR 1, FSR 2, FSR 3 and later are software/game integrations. They are not a GPU driver switch and cannot be established from a GPU name or driver version."]
    return {
        "status_meanings": {
            "detected": "A local probe supplied direct API, runtime, or media-driver evidence for the stated scope.",
            "likely_eligible_by_architecture": "A locally reported architecture is consistent with the feature family; it is not a driver, game, or application enablement result.",
            "unknown": "No reliable local evidence was available. Unknown is not the same as unsupported.",
        },
        "architecture_evidence": architectures,
        "features": {
            "fidelityfx_super_resolution": _feature("unknown", "software_game_integration", [], fsr_notes),
            "fluid_motion_frames_afmf": _feature("unknown", "AMD_software_driver_feature", [], ["AFMF availability depends on AMD Software version, OS, GPU support, game settings, and current driver policy. Inventory and tool presence do not prove it is available or enabled."]),
            "hypr_rx": _feature("unknown", "AMD_software_driver_preset", [], ["HYPR-RX is an AMD Software preset. No documented cross-platform command-line query was observed that proves its availability or active state."]),
            "anti_lag": _feature("unknown", "AMD_software_driver_feature", [], ["Anti-Lag availability and enabled state are controlled by AMD Software and may vary by game, API, driver, and policy." ]),
            "radeon_super_resolution_rsr": _feature("unknown", "AMD_software_driver_feature", [], ["RSR is a driver-level feature, but a detected AMD device or driver version is not proof that the feature is supported or enabled."]),
            "ray_tracing": ray,
            "vcn_hardware_encode_decode": media,
            "rocm_hip": _feature("detected" if hip_runtime else "unknown", "compute_runtime", ["rocminfo enumerated one or more AMD gfx agents"] if hip_runtime else [],
                                  ["hipcc/hipconfig presence alone only proves installed tooling; successful rocminfo agent enumeration is used as runtime evidence."] +
                                  (["hipcc is available"] if tool_probes["hipcc"]["status"] == "ok" else []) + (["hipconfig is available"] if tool_probes["hipconfig"]["status"] == "ok" else []),
                                  "ROCm runtime" if hip_runtime else "unknown"),
            "vulkan_extension_evidence": _feature("detected" if api["vulkan_extensions"] else "unknown", "graphics_api_extension",
                                                    ["vulkaninfo reported " + item for item in api["vulkan_extensions"]],
                                                    [api["limitations"]], "Vulkan runtime" if api["vulkan_extensions"] else "unknown"),
            "direct3d_api_evidence": direct3d,
            "vulkan_video_extension_hint": _feature("detected" if video_extensions & extension_set else "unknown", "graphics_api_extension",
                                                       ["vulkaninfo reported " + item for item in sorted(video_extensions & extension_set)],
                                                       ["Vulkan Video extension support is distinct from AMD VCN codec support and may not be tied to a particular AMD device."], "Vulkan runtime" if video_extensions & extension_set else "unknown"),
        },
    }


def collect_amd_info() -> dict[str, Any]:
    """Return the stable public report; all probes are read-only and optional."""
    system = platform.system()
    probes: dict[str, Any] = {}
    devices: list[dict[str, Any]] = []
    architectures: list[dict[str, Any]] = []
    dxdiag: dict[str, Any] = {"directx_version": None, "display_devices": [], "limitations": "not applicable"}
    lspci_records: list[dict[str, Any]] = []
    if system == "Windows":
        probes["windows_cim"], devices = _powershell_cim()
        probes["dxdiag"], dxdiag = _dxdiag()
    elif system == "Linux":
        probes["linux_sysfs"], devices, architectures = _linux_sysfs()
        probes["lspci"], lspci_records = _linux_lspci()
    else:
        probes["windows_cim"] = {"found": False, "status": "not applicable", "path": None, "command": None, "exit_code": None}
        probes["linux_sysfs"] = {"found": False, "status": "not applicable", "path": None, "command": None, "exit_code": None}
    tools, tool_outputs, rocm_agents = _tool_probes()
    # rocminfo is a second, independent architecture source. Keep it rather
    # than merging records by names, because names must never drive inference.
    for item in rocm_agents:
        if item not in architectures:
            architectures.append(item)
    api, extension_set = _api_evidence()
    probes["vulkaninfo"] = {**api["vulkaninfo"], "amd_physical_devices": api["amd_physical_devices"]}
    driver_sources: list[dict[str, Any]] = []
    for device in devices:
        if device.get("driver"):
            driver_sources.append({"source": ",".join(device.get("sources", [])), "driver": device["driver"]})
    report = {
        "schema_version": 1,
        "platform": {"operating_system": system, "operating_system_release": platform.release(), "machine": platform.machine()},
        "availability": {"amd_device_detected": bool(devices or lspci_records), "amd_driver_evidence": bool(driver_sources),
                         "rocm_runtime_detected": tools["rocminfo"]["status"] == "ok" and bool(rocm_agents),
                         "vulkan_api_evidence": bool(api["vulkan_extensions"])},
        "driver": {"sources": driver_sources, "dxdiag": dxdiag, "linux_lspci_amd_display_records": lspci_records},
        "devices": devices,
        "tools": tools,
        "probes": probes,
        "capabilities": _capabilities(system, architectures, api, extension_set, tools, tool_outputs, dxdiag),
        "limitations": [
            "This is a read-only inventory. It does not launch a game, render workload, encoder, ROCm kernel, or AMD Software control panel.",
            "GPU product names and PCI IDs are retained as identity evidence only; they are not used as proof of optional capabilities.",
            "On multi-GPU systems, Vulkan and DXDiag evidence may need manual correlation with PCI/device identity.",
        ],
    }
    return _compact(report)


def _human(report: dict[str, Any]) -> None:
    availability = report["availability"]
    print("AMD GPU: " + ("detected" if availability["amd_device_detected"] else "not detected"))
    print("Driver evidence: %s | ROCm runtime: %s | Vulkan evidence: %s" %
          ("yes" if availability["amd_driver_evidence"] else "no", "yes" if availability["rocm_runtime_detected"] else "no", "yes" if availability["vulkan_api_evidence"] else "no"))
    for index, device in enumerate(report["devices"]):
        identity, driver = device.get("identity", {}), device.get("driver", {})
        print("GPU %d: %s | PCI %s | driver %s" % (index, identity.get("name") or "AMD GPU (unnamed)", identity.get("pci_address") or identity.get("pnp_device_id") or "unknown", driver.get("driver_version") or driver.get("kernel_driver") or "unknown"))
    for name, feature in report["capabilities"]["features"].items():
        print("%s: %s" % (name, feature["status"]))
    if not report["devices"]:
        print("No AMD device was enumerated. Inspect --json probes for platform/tool evidence.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Report AMD GPU, driver, runtime, and API capability evidence without GPU-name inference.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    args = parser.parse_args()
    report = collect_amd_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
