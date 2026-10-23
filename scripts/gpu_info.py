#!/usr/bin/env python3
# description: Consolidated GPU inventory and graphics, compute, and vendor capability reporter.
"""Collect GPU inventory, API, and vendor capability evidence from one file.

Each embedded collector keeps its original report schema.  Private implementation
symbols are namespaced per collector so optional probes remain independent.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

# Embedded amd_info collector implementation.
_amd_AMD_PCI_VENDOR = '0x1002'

def _amd_read(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace').strip() or None
    except OSError:
        return None

def _amd_run(*command: str, timeout: int=20) -> tuple[str | None, int | None, str | None]:
    """Run an optional read-only probe and retain a compact diagnostic."""
    if not command or not shutil.which(command[0]):
        return (None, None, 'not installed or not on PATH')
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        output = (result.stdout or '') + ('\n' + result.stderr if result.stderr else '')
        return (output, result.returncode, None if result.returncode == 0 else 'exited with %d' % result.returncode)
    except subprocess.TimeoutExpired:
        return (None, None, 'timed out')
    except OSError as error:
        return (None, None, type(error).__name__)

def _amd_probe(command: list[str], timeout: int=20) -> tuple[dict[str, Any], str | None]:
    path = shutil.which(command[0])
    base: dict[str, Any] = {'found': bool(path), 'path': path, 'command': command, 'status': 'not installed' if not path else 'not run', 'exit_code': None}
    if not path:
        return (base, None)
    output, code, error = _amd_run(*command, timeout=timeout)
    base.update({'status': 'ok' if code == 0 else 'unavailable', 'exit_code': code, 'error': error})
    return (base, output)

def _amd_integer(value: Any) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None

def _amd_compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _amd_compact(item) for key, item in value.items() if item not in (None, '')}
    if isinstance(value, list):
        return [_amd_compact(item) for item in value]
    return value

def _amd_is_amd_record(record: dict[str, Any]) -> bool:
    identity = ' '.join((str(record.get(key) or '') for key in ('pnp_device_id', 'adapter_compatibility', 'manufacturer', 'vendor')))
    return 'VEN_1002' in identity.upper() or bool(re.search('\\b(AMD|ATI|ADVANCED MICRO DEVICES)\\b', identity, re.I))

def _amd_powershell_cim() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    command = ['powershell', '-NoProfile', '-NonInteractive', '-Command', '$x=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,PNPDeviceID,DriverVersion,DriverDate,DriverName,InstalledDisplayDrivers,VideoProcessor,AdapterRAM,CurrentHorizontalResolution,CurrentVerticalResolution); $x | ConvertTo-Json -Depth 3 -Compress']
    probe, output = _amd_probe(command, timeout=25)
    probe['source'] = 'Win32_VideoController (CIM)'
    if not output or probe['status'] != 'ok':
        return (probe, [])
    try:
        decoded = json.loads(output)
    except json.JSONDecodeError:
        probe.update({'status': 'unavailable', 'error': 'CIM output was not JSON'})
        return (probe, [])
    rows = decoded if isinstance(decoded, list) else [decoded]
    devices: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        record = {'name': row.get('Name'), 'adapter_compatibility': row.get('AdapterCompatibility'), 'pnp_device_id': row.get('PNPDeviceID'), 'driver_version': row.get('DriverVersion'), 'driver_date': row.get('DriverDate'), 'driver_name': row.get('DriverName'), 'installed_display_drivers': row.get('InstalledDisplayDrivers'), 'video_processor': row.get('VideoProcessor'), 'memory_bytes': _amd_integer(row.get('AdapterRAM')), 'current_resolution': '%sx%s' % (row.get('CurrentHorizontalResolution'), row.get('CurrentVerticalResolution')) if row.get('CurrentHorizontalResolution') and row.get('CurrentVerticalResolution') else None}
        if _amd_is_amd_record(record):
            devices.append(_amd_compact({'identity': {'vendor_id': _amd_AMD_PCI_VENDOR, 'name': record['name'], 'pnp_device_id': record['pnp_device_id']}, 'driver': _amd_compact({key: record[key] for key in ('adapter_compatibility', 'driver_version', 'driver_date', 'driver_name', 'installed_display_drivers', 'video_processor')}), 'memory_bytes': record['memory_bytes'], 'current_resolution': record['current_resolution'], 'sources': ['windows_cim']}))
    return (probe, devices)

def _amd_dxdiag() -> tuple[dict[str, Any], dict[str, Any]]:
    """Read DirectX diagnostic data, if Windows supplies dxdiag.

    dxdiag has no reliable API for optional D3D extensions.  Its DDI and
    feature-level fields are preserved as API evidence only.
    """
    executable = shutil.which('dxdiag')
    if not executable and platform.system() == 'Windows':
        candidate = Path(os.environ.get('SystemRoot', 'C:\\\\Windows')) / 'System32' / 'dxdiag.exe'
        executable = str(candidate) if candidate.is_file() else None
    probe: dict[str, Any] = {'found': bool(executable), 'path': executable, 'command': ['dxdiag', '/x', '<temporary-file>'], 'status': 'not installed' if not executable else 'not run', 'exit_code': None}
    details: dict[str, Any] = {'directx_version': None, 'display_devices': [], 'limitations': 'DXDiag DDI/feature levels are not evidence of ray tracing or driver-control features.'}
    if not executable:
        return (probe, details)
    try:
        with tempfile.TemporaryDirectory(prefix='amd-info-') as directory:
            target = Path(directory) / 'dxdiag.xml'
            result = subprocess.run([executable, '/x', str(target)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
            probe.update({'exit_code': result.returncode, 'status': 'ok' if result.returncode == 0 and target.is_file() else 'unavailable', 'error': None if result.returncode == 0 and target.is_file() else 'DXDiag did not create XML'})
            if probe['status'] != 'ok':
                return (probe, details)
            root = ET.parse(target).getroot()
            details['directx_version'] = root.findtext('./SystemInformation/DirectXVersion')
            for item in root.findall('.//DisplayDevice'):
                vendor = item.findtext('Manufacturer') or ''
                device_id = item.findtext('DeviceID') or ''
                if not _amd_is_amd_record({'manufacturer': vendor, 'pnp_device_id': device_id}):
                    continue
                details['display_devices'].append(_amd_compact({'name': item.findtext('CardName'), 'manufacturer': vendor, 'device_id': device_id, 'driver_version': item.findtext('DriverVersion'), 'driver_date': item.findtext('DriverDate'), 'ddi_version': item.findtext('DDIVersion'), 'feature_levels': item.findtext('FeatureLevels')}))
    except (OSError, subprocess.TimeoutExpired, ET.ParseError) as error:
        probe.update({'status': 'unavailable', 'error': type(error).__name__})
    return (probe, details)

def _amd_linux_sysfs() -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    probe: dict[str, Any] = {'found': sys.platform.startswith('linux'), 'path': '/sys/class/drm', 'command': None, 'status': 'not applicable', 'exit_code': None}
    devices: list[dict[str, Any]] = []
    architectures: list[dict[str, Any]] = []
    if not sys.platform.startswith('linux'):
        return (probe, devices, architectures)
    root = Path('/sys/class/drm')
    if not root.is_dir():
        probe.update({'status': 'unavailable', 'error': 'DRM sysfs directory is absent'})
        return (probe, devices, architectures)
    for card in sorted(root.glob('card[0-9]*')):
        device = card / 'device'
        if _amd_read(device / 'vendor') != _amd_AMD_PCI_VENDOR:
            continue
        driver_link = device / 'driver'
        try:
            driver = driver_link.resolve().name if driver_link.exists() else None
        except OSError:
            driver = None
        devices.append(_amd_compact({'identity': {'vendor_id': _amd_AMD_PCI_VENDOR, 'pci_device_id': _amd_read(device / 'device'), 'pci_revision': _amd_read(device / 'revision'), 'pci_address': device.resolve().name}, 'driver': {'kernel_driver': driver, 'module_version': _amd_read('/sys/module/amdgpu/version')}, 'drm_card': card.name, 'render_nodes': [node.name for node in root.glob('renderD*') if node.resolve().parent == card.resolve().parent], 'sources': ['linux_sysfs']}))
    kfd = Path('/sys/class/kfd/kfd/topology/nodes')
    for node in sorted(kfd.glob('*/properties')):
        values: dict[str, str] = {}
        for line in (_amd_read(node) or '').splitlines():
            parts = line.split()
            if len(parts) >= 2:
                values[parts[0]] = parts[1]
        if _amd_integer(values.get('vendor_id')) != 4098:
            continue
        raw = _amd_integer(values.get('gfx_target_version'))
        gfxip = 'gfx%d' % (raw // 100) if raw else None
        architectures.append(_amd_compact({'node': node.parent.name, 'gfxip': gfxip, 'gfx_target_version': raw, 'source': 'linux_kfd_topology', 'generation': _amd_gfx_generation(gfxip)}))
    probe.update({'status': 'ok', 'device_count': len(devices), 'kfd_architecture_count': len(architectures)})
    return (probe, devices, architectures)

def _amd_linux_lspci() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe, output = _amd_probe(['lspci', '-Dnns'], timeout=15)
    probe['source'] = 'lspci numeric PCI inventory'
    records: list[dict[str, Any]] = []
    if not output or probe['status'] != 'ok':
        return (probe, records)
    for line in output.splitlines():
        match = re.match('^(\\S+)\\s+([0-9a-fA-F]{4}):\\s+1002:([0-9a-fA-F]{4})(?:\\s+\\(rev\\s+([0-9a-fA-F]+)\\))?\\s*(.*)$', line)
        if match and match.group(2).lower().startswith('03'):
            records.append({'pci_address': match.group(1), 'class_code': '0x' + match.group(2), 'vendor_id': _amd_AMD_PCI_VENDOR, 'pci_device_id': '0x' + match.group(3).lower(), 'pci_revision': '0x' + match.group(4).lower() if match.group(4) else None, 'description': match.group(5) or None})
    probe['amd_display_count'] = len(records)
    return (probe, records)

def _amd_gfx_generation(gfxip: str | None) -> str | None:
    value = _amd_integer((gfxip or '').replace('gfx', ''))
    if value is None:
        return None
    if value >= 1200:
        return 'RDNA 4 or later'
    if value >= 1100:
        return 'RDNA 3'
    if value >= 1030:
        return 'RDNA 2'
    if value >= 1000:
        return 'RDNA'
    if value >= 900:
        return 'GCN 5 / Vega'
    return 'pre-RDNA / unknown generation'

def _amd_tool_probes() -> tuple[dict[str, Any], dict[str, str | None], list[dict[str, Any]]]:
    """Probe optional AMD diagnostics without assuming their output formats."""
    probes: dict[str, Any] = {}
    outputs: dict[str, str | None] = {}
    for key, command in {'rocm_smi': ['rocm-smi', '--showproductname', '--showdriverversion', '--showuniqueid'], 'amdgpu_top': ['amdgpu_top', '--version'], 'radeontop': ['radeontop', '--version'], 'rocminfo': ['rocminfo'], 'hipcc': ['hipcc', '--version'], 'hipconfig': ['hipconfig', '--version'], 'vainfo': ['vainfo']}.items():
        timeout = 35 if key == 'rocminfo' else 15
        probe, output = _amd_probe(command, timeout=timeout)
        probes[key] = probe
        outputs[key] = output
    agents: list[dict[str, Any]] = []
    if probes['rocminfo']['status'] == 'ok':
        for match in re.finditer('(?im)^\\s*Name:\\s*(gfx[0-9a-f]+)\\s*$', outputs['rocminfo'] or ''):
            gfxip = match.group(1).lower()
            agents.append({'gfxip': gfxip, 'generation': _amd_gfx_generation(gfxip), 'source': 'rocminfo'})
    return (probes, outputs, agents)

def _amd_vulkan_value(mapping: dict[str, Any], names: set[str]) -> Any:
    """Find a field in a device object or one of its direct property maps."""
    for key, value in mapping.items():
        if key.replace('_', '').lower() in names:
            return value
    for value in mapping.values():
        if isinstance(value, dict):
            for key, nested in value.items():
                if key.replace('_', '').lower() in names:
                    return nested
    return None

def _amd_vulkan_vendor_id(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or '').strip()
    try:
        return int(text, 0)
    except ValueError:
        return int(text, 16) if re.fullmatch('[0-9a-fA-F]{4}', text) else None

def _amd_vulkan_extension_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key.replace('_', '').lower() in {'extensionname', 'extension'} and isinstance(item, str) and item.startswith('VK_'):
                names.add(item)
            names.update(_amd_vulkan_extension_names(item))
    elif isinstance(value, list):
        for item in value:
            names.update(_amd_vulkan_extension_names(item))
    elif isinstance(value, str) and value.startswith('VK_'):
        names.add(value)
    return names

def _amd_amd_vulkan_devices(document: Any) -> list[dict[str, Any]]:
    """Extract extensions only from a JSON object scoped to AMD vendor ID.

    ``vulkaninfo`` JSON formats differ between SDK releases.  We intentionally
    identify device containers by a vendorID field (including a direct
    properties child), then collect extension names beneath that same container.
    A global/instance extension list is never used as AMD device evidence.
    """
    records: list[dict[str, Any]] = []

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            vendor = _amd_vulkan_vendor_id(_amd_vulkan_value(value, {'vendorid'}))
            if vendor == 4098:
                extensions = sorted(_amd_vulkan_extension_names(value))
                name = _amd_vulkan_value(value, {'devicename'})
                records.append({'vendor_id': _amd_AMD_PCI_VENDOR, 'device_name': name if isinstance(name, str) else None, 'extensions': extensions})
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

def _amd_api_evidence() -> tuple[dict[str, Any], set[str]]:
    path = shutil.which('vulkaninfo')
    probe: dict[str, Any] = {'found': bool(path), 'path': path, 'command': ['vulkaninfo', '--json'], 'status': 'not installed' if not path else 'not run', 'exit_code': None}
    document: Any = None
    if path:
        try:
            with tempfile.TemporaryDirectory(prefix='amd-info-vulkan-') as directory:
                result = subprocess.run([path, '--json'], cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
                if result.returncode != 0:
                    probe.update({'status': 'unavailable', 'exit_code': result.returncode, 'error': 'exited with %d' % result.returncode})
                else:
                    reports = sorted(Path(directory).glob('VP_VULKANINFO_*.json'))
                    raw = reports[0].read_text(encoding='utf-8') if reports else result.stdout
                    try:
                        document = json.loads(raw)
                        probe.update({'status': 'ok', 'exit_code': result.returncode, 'error': None})
                    except json.JSONDecodeError:
                        probe.update({'status': 'unavailable', 'exit_code': result.returncode, 'error': 'vulkaninfo did not emit valid JSON'})
        except subprocess.TimeoutExpired:
            probe.update({'status': 'unavailable', 'error': 'timed out'})
        except OSError as error:
            probe.update({'status': 'unavailable', 'error': type(error).__name__})
    devices = _amd_amd_vulkan_devices(document) if document is not None and probe['status'] == 'ok' else []
    extensions = sorted({extension for device in devices for extension in device['extensions']})
    selected = [item for item in extensions if item.startswith('VK_AMD_') or item in {'VK_KHR_acceleration_structure', 'VK_KHR_ray_query', 'VK_KHR_ray_tracing_pipeline', 'VK_KHR_video_decode_queue', 'VK_KHR_video_encode_queue'}]
    return ({'vulkaninfo': probe, 'amd_physical_devices': devices, 'vulkan_extensions': selected, 'limitations': 'Only extensions beneath a vulkaninfo JSON physical-device object with vendorID 0x1002 are used as AMD evidence. Other Vulkan devices and instance extensions are excluded.'}, set(extensions))

def _amd_feature(status: str, classification: str, evidence: list[str], notes: list[str], scope: str='unknown') -> dict[str, Any]:
    return {'status': status, 'classification': classification, 'scope': scope, 'evidence': evidence, 'notes': notes}

def _amd_has_gfx_at_least(architectures: list[dict[str, Any]], minimum: int) -> bool:
    return any(((_amd_integer(str(item.get('gfxip') or '').replace('gfx', '')) or 0) >= minimum for item in architectures))

def _amd_capabilities(system: str, architectures: list[dict[str, Any]], api: dict[str, Any], extension_set: set[str], tool_probes: dict[str, Any], tool_outputs: dict[str, str | None], dxdiag: dict[str, Any]) -> dict[str, Any]:
    ray_extensions = {'VK_KHR_acceleration_structure', 'VK_KHR_ray_query', 'VK_KHR_ray_tracing_pipeline'}
    video_extensions = {'VK_KHR_video_decode_queue', 'VK_KHR_video_encode_queue'}
    va_output = tool_outputs.get('vainfo') or ''
    amd_va = bool(re.search('radeonsi|AMD', va_output, re.I))
    va_decode = bool(re.search('VAEntrypointVLD', va_output))
    va_encode = bool(re.search('VAEntrypointEnc', va_output))
    hip_runtime = tool_probes['rocminfo']['status'] == 'ok' and bool(architectures)
    ray_evidence = sorted(ray_extensions & extension_set)
    if ray_evidence:
        ray = _amd_feature('detected', 'graphics_api_extension', ['vulkaninfo reported ' + item for item in ray_evidence], ['This is Vulkan runtime evidence; inspect device association when more than one GPU is present.'], 'Vulkan runtime')
    elif _amd_has_gfx_at_least(architectures, 1030):
        ray = _amd_feature('likely_eligible_by_architecture', 'architecture_inference', ['KFD/ROCm reported an RDNA 2-or-later gfx target'], ['Architecture eligibility is not proof that a driver, API, or application exposes ray tracing.'], 'Linux AMD GPU with KFD/ROCm architecture evidence')
    else:
        ray = _amd_feature('unknown', 'hardware_and_api_feature', [], ['No AMD-correlated ray-tracing API extension or architecture evidence was observed.'])
    if amd_va and (va_decode or va_encode):
        media = _amd_feature('detected', 'VA_API_media_entrypoints', ['vainfo identified an AMD/radeonsi VA driver'] + (['VAEntrypointVLD (decode)'] if va_decode else []) + (['VAEntrypointEnc* (encode)'] if va_encode else []), ['VA-API entrypoints describe the active Linux media driver; they do not enumerate every codec/profile or prove Windows AMF support.'], 'active VA-API driver')
    elif _amd_has_gfx_at_least(architectures, 900):
        media = _amd_feature('likely_eligible_by_architecture', 'architecture_inference', ['KFD/ROCm reported a gfx9-or-later target'], ['This only suggests a VCN-era media block. Exact VCN generation, codecs, and encode/decode support remain unknown without a media API report.'], 'Linux AMD GPU with KFD/ROCm architecture evidence')
    else:
        media = _amd_feature('unknown', 'hardware_media_feature', [], ['No AMD-correlated VA-API or architecture evidence was observed.'])
    dx_devices = dxdiag.get('display_devices') or []
    dx_evidence: list[str] = []
    for device in dx_devices:
        if device.get('ddi_version'):
            dx_evidence.append('DXDiag DDI version %s' % device['ddi_version'])
        if device.get('feature_levels'):
            dx_evidence.append('DXDiag feature levels %s' % device['feature_levels'])
    direct3d = _amd_feature('detected' if dx_evidence else 'unknown', 'diagnostic_API_evidence', dx_evidence, ['DXDiag DDI/feature levels describe Direct3D diagnostic API evidence only. They are not an extension inventory and do not prove ray tracing or AMD Software features.'], 'AMD DXDiag display device' if dx_evidence else 'unknown')
    fsr_notes = ['FSR 1, FSR 2, FSR 3 and later are software/game integrations. They are not a GPU driver switch and cannot be established from a GPU name or driver version.']
    return {'status_meanings': {'detected': 'A local probe supplied direct API, runtime, or media-driver evidence for the stated scope.', 'likely_eligible_by_architecture': 'A locally reported architecture is consistent with the feature family; it is not a driver, game, or application enablement result.', 'unknown': 'No reliable local evidence was available. Unknown is not the same as unsupported.'}, 'architecture_evidence': architectures, 'features': {'fidelityfx_super_resolution': _amd_feature('unknown', 'software_game_integration', [], fsr_notes), 'fluid_motion_frames_afmf': _amd_feature('unknown', 'AMD_software_driver_feature', [], ['AFMF availability depends on AMD Software version, OS, GPU support, game settings, and current driver policy. Inventory and tool presence do not prove it is available or enabled.']), 'hypr_rx': _amd_feature('unknown', 'AMD_software_driver_preset', [], ['HYPR-RX is an AMD Software preset. No documented cross-platform command-line query was observed that proves its availability or active state.']), 'anti_lag': _amd_feature('unknown', 'AMD_software_driver_feature', [], ['Anti-Lag availability and enabled state are controlled by AMD Software and may vary by game, API, driver, and policy.']), 'radeon_super_resolution_rsr': _amd_feature('unknown', 'AMD_software_driver_feature', [], ['RSR is a driver-level feature, but a detected AMD device or driver version is not proof that the feature is supported or enabled.']), 'ray_tracing': ray, 'vcn_hardware_encode_decode': media, 'rocm_hip': _amd_feature('detected' if hip_runtime else 'unknown', 'compute_runtime', ['rocminfo enumerated one or more AMD gfx agents'] if hip_runtime else [], ['hipcc/hipconfig presence alone only proves installed tooling; successful rocminfo agent enumeration is used as runtime evidence.'] + (['hipcc is available'] if tool_probes['hipcc']['status'] == 'ok' else []) + (['hipconfig is available'] if tool_probes['hipconfig']['status'] == 'ok' else []), 'ROCm runtime' if hip_runtime else 'unknown'), 'vulkan_extension_evidence': _amd_feature('detected' if api['vulkan_extensions'] else 'unknown', 'graphics_api_extension', ['vulkaninfo reported ' + item for item in api['vulkan_extensions']], [api['limitations']], 'Vulkan runtime' if api['vulkan_extensions'] else 'unknown'), 'direct3d_api_evidence': direct3d, 'vulkan_video_extension_hint': _amd_feature('detected' if video_extensions & extension_set else 'unknown', 'graphics_api_extension', ['vulkaninfo reported ' + item for item in sorted(video_extensions & extension_set)], ['Vulkan Video extension support is distinct from AMD VCN codec support and may not be tied to a particular AMD device.'], 'Vulkan runtime' if video_extensions & extension_set else 'unknown')}}

def _amd_collect_amd_info(skip_dxdiag: bool=False) -> dict[str, Any]:
    """Return the stable public report; all probes are read-only and optional."""
    system = platform.system()
    probes: dict[str, Any] = {}
    devices: list[dict[str, Any]] = []
    architectures: list[dict[str, Any]] = []
    dxdiag: dict[str, Any] = {'directx_version': None, 'display_devices': [], 'limitations': 'not applicable'}
    lspci_records: list[dict[str, Any]] = []
    if system == 'Windows':
        probes['windows_cim'], devices = _amd_powershell_cim()
        if skip_dxdiag:
            probes['dxdiag'] = {'found': False, 'status': 'skipped', 'path': None, 'command': ['dxdiag', '/x', '<temporary-file>'], 'exit_code': None, 'reason': 'requested by consolidated GPU report'}
            dxdiag = {'directx_version': None, 'display_devices': [], 'limitations': 'DxDiag was skipped by the consolidated GPU report.'}
        else:
            probes['dxdiag'], dxdiag = _amd_dxdiag()
    elif system == 'Linux':
        probes['linux_sysfs'], devices, architectures = _amd_linux_sysfs()
        probes['lspci'], lspci_records = _amd_linux_lspci()
    else:
        probes['windows_cim'] = {'found': False, 'status': 'not applicable', 'path': None, 'command': None, 'exit_code': None}
        probes['linux_sysfs'] = {'found': False, 'status': 'not applicable', 'path': None, 'command': None, 'exit_code': None}
    tools, tool_outputs, rocm_agents = _amd_tool_probes()
    for item in rocm_agents:
        if item not in architectures:
            architectures.append(item)
    api, extension_set = _amd_api_evidence()
    probes['vulkaninfo'] = {**api['vulkaninfo'], 'amd_physical_devices': api['amd_physical_devices']}
    driver_sources: list[dict[str, Any]] = []
    for device in devices:
        if device.get('driver'):
            driver_sources.append({'source': ','.join(device.get('sources', [])), 'driver': device['driver']})
    report = {'schema_version': 1, 'platform': {'operating_system': system, 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'availability': {'amd_device_detected': bool(devices or lspci_records), 'amd_driver_evidence': bool(driver_sources), 'rocm_runtime_detected': tools['rocminfo']['status'] == 'ok' and bool(rocm_agents), 'vulkan_api_evidence': bool(api['vulkan_extensions'])}, 'driver': {'sources': driver_sources, 'dxdiag': dxdiag, 'linux_lspci_amd_display_records': lspci_records}, 'devices': devices, 'tools': tools, 'probes': probes, 'capabilities': _amd_capabilities(system, architectures, api, extension_set, tools, tool_outputs, dxdiag), 'limitations': ['This is a read-only inventory. It does not launch a game, render workload, encoder, ROCm kernel, or AMD Software control panel.', 'GPU product names and PCI IDs are retained as identity evidence only; they are not used as proof of optional capabilities.', 'On multi-GPU systems, Vulkan and DXDiag evidence may need manual correlation with PCI/device identity.']}
    return _amd_compact(report)

def _amd_human(report: dict[str, Any]) -> None:
    availability = report['availability']
    print('AMD GPU: ' + ('detected' if availability['amd_device_detected'] else 'not detected'))
    print('Driver evidence: %s | ROCm runtime: %s | Vulkan evidence: %s' % ('yes' if availability['amd_driver_evidence'] else 'no', 'yes' if availability['rocm_runtime_detected'] else 'no', 'yes' if availability['vulkan_api_evidence'] else 'no'))
    for index, device in enumerate(report['devices']):
        identity, driver = (device.get('identity', {}), device.get('driver', {}))
        print('GPU %d: %s | PCI %s | driver %s' % (index, identity.get('name') or 'AMD GPU (unnamed)', identity.get('pci_address') or identity.get('pnp_device_id') or 'unknown', driver.get('driver_version') or driver.get('kernel_driver') or 'unknown'))
    for name, feature in report['capabilities']['features'].items():
        print('%s: %s' % (name, feature['status']))
    if not report['devices']:
        print('No AMD device was enumerated. Inspect --json probes for platform/tool evidence.')

def _amd_main() -> int:
    parser = argparse.ArgumentParser(description='Report AMD GPU, driver, runtime, and API capability evidence without GPU-name inference.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _amd_collect_amd_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _amd_human(report)
    return 0

# Embedded cuda_info collector implementation.
def _cuda_run(*command: str) -> tuple[str | None, int | None]:
    if not command or not shutil.which(command[0]):
        return (None, None)
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        return (result.stdout, result.returncode)
    except (OSError, subprocess.TimeoutExpired):
        return (None, None)

def _cuda_version(value: int | None) -> str | None:
    if value is None:
        return None
    return f'{value // 1000}.{value % 1000 // 10}' if value >= 1000 else str(value)

def _cuda_candidate_roots() -> list[str]:
    roots: list[Path] = []
    for name in ('CUDA_PATH', 'CUDA_HOME', 'CUDA_ROOT'):
        if os.environ.get(name):
            roots.append(Path(os.environ[name]))
    if sys.platform == 'win32':
        base = Path(os.environ.get('ProgramFiles', 'C:\\\\Program Files')) / 'NVIDIA GPU Computing Toolkit' / 'CUDA'
        if base.is_dir():
            roots.extend((item for item in base.iterdir() if item.is_dir()))
    elif sys.platform.startswith('linux'):
        roots.extend((Path(item) for item in ('/usr/local/cuda', '/opt/cuda') if Path(item).is_dir()))
        roots.extend(sorted(Path('/usr/local').glob('cuda-*')))
    elif sys.platform == 'darwin':
        roots.extend((Path(item) for item in ('/usr/local/cuda', '/Developer/NVIDIA/CUDA-*/') if Path(item).exists()))
    return sorted({str(path.resolve()) for path in roots if path.exists()})

def _cuda_library_candidates(roots: list[str]) -> list[str]:
    names = ('cudart64*.dll', 'cudart*.dll') if sys.platform == 'win32' else ('libcudart.so*', 'libcuda.so*')
    values: set[str] = set()
    for root in roots:
        for directory in (Path(root) / 'bin', Path(root) / 'lib', Path(root) / 'lib64'):
            if directory.is_dir():
                for pattern in names:
                    values.update((str(path) for path in directory.glob(pattern)))
    for library in (ctypes.util.find_library('cudart'), ctypes.util.find_library('cuda')):
        if library:
            values.add(library)
    return sorted(values)

def _cuda_load_driver() -> tuple[Any | None, str | None]:
    names = ['nvcuda.dll'] if sys.platform == 'win32' else ['libcuda.so.1', 'libcuda.so']
    located = ctypes.util.find_library('cuda')
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == 'win32' else ctypes.CDLL
    for name in names:
        try:
            return (loader(name), name)
        except OSError:
            continue
    return (None, None)

def _cuda_driver_api() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    base = {'available': False, 'library': None, 'status': 'CUDA Driver API library was not found', 'driver_version_raw': None, 'driver_version': None}
    library, library_name = _cuda_load_driver()
    base['library'] = library_name
    if library is None:
        return (base, [])
    try:
        library.cuInit.argtypes = [ctypes.c_uint]
        library.cuInit.restype = ctypes.c_int
        result = library.cuInit(0)
        if result != 0:
            base['status'] = f'cuInit failed with CUDA result {result}'
            return (base, [])
        library.cuDriverGetVersion.argtypes = [ctypes.POINTER(ctypes.c_int)]
        library.cuDriverGetVersion.restype = ctypes.c_int
        version = ctypes.c_int()
        if library.cuDriverGetVersion(ctypes.byref(version)) == 0:
            base['driver_version_raw'] = version.value
            base['driver_version'] = _cuda_version(version.value)
        library.cuDeviceGetCount.argtypes = [ctypes.POINTER(ctypes.c_int)]
        library.cuDeviceGetCount.restype = ctypes.c_int
        count = ctypes.c_int()
        if library.cuDeviceGetCount(ctypes.byref(count)) != 0:
            base['status'] = 'CUDA driver initialized but device enumeration failed'
            return (base, [])
        base.update({'available': True, 'status': 'available', 'device_count': count.value})
        library.cuDeviceGet.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        library.cuDeviceGet.restype = ctypes.c_int
        library.cuDeviceGetName.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        library.cuDeviceGetName.restype = ctypes.c_int
        library.cuDeviceComputeCapability.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        library.cuDeviceComputeCapability.restype = ctypes.c_int
        library.cuDeviceGetAttribute.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_int, ctypes.c_int]
        library.cuDeviceGetAttribute.restype = ctypes.c_int
        total_memory = getattr(library, 'cuDeviceTotalMem_v2', None)
        if total_memory is None:
            total_memory = getattr(library, 'cuDeviceTotalMem', None)
        if total_memory:
            total_memory.argtypes = [ctypes.POINTER(ctypes.c_size_t), ctypes.c_int]
            total_memory.restype = ctypes.c_int
        attributes = {'max_threads_per_block': 1, 'max_block_dimensions': (2, 3, 4), 'max_grid_dimensions': (5, 6, 7), 'max_shared_memory_per_block_bytes': 8, 'total_constant_memory_bytes': 9, 'warp_size': 10, 'max_registers_per_block': 12, 'clock_rate_khz': 13, 'texture_alignment_bytes': 14, 'gpu_overlap': 15, 'multiprocessor_count': 16, 'kernel_execution_timeout': 17, 'integrated': 18, 'can_map_host_memory': 19, 'compute_mode': 20, 'unified_addressing': 41, 'pci_bus_id': 33, 'pci_device_id': 34, 'pci_domain_id': 50, 'ecc_enabled': 32, 'concurrent_kernels': 31, 'managed_memory': 83, 'concurrent_managed_access': 89, 'pageable_memory_access': 88, 'memory_pools_supported': 115, 'virtual_memory_management_supported': 102}
        devices: list[dict[str, Any]] = []
        for index in range(count.value):
            device = ctypes.c_int()
            if library.cuDeviceGet(ctypes.byref(device), index) != 0:
                continue
            name = ctypes.create_string_buffer(256)
            library.cuDeviceGetName(name, len(name), device.value)
            major, minor = (ctypes.c_int(), ctypes.c_int())
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
            devices.append({'index': index, 'name': name.value.decode(errors='replace') or None, 'compute_capability': f'{major.value}.{minor.value}' if major.value or minor.value else None, 'total_memory_bytes': memory.value if total_memory and total_memory(ctypes.byref(memory), device.value) == 0 else None, 'driver_api_limits': limits})
        return (base, devices)
    except (AttributeError, OSError, ValueError) as error:
        base['status'] = f'Driver API probe failed: {type(error).__name__}'
        return (base, [])

def _cuda_nvidia_smi() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = shutil.which('nvidia-smi')
    probe: dict[str, Any] = {'available': False, 'path': path, 'status': 'nvidia-smi was not found', 'cuda_version': None}
    if not path:
        return (probe, [])
    fields = 'index,name,uuid,pci.bus_id,driver_version,vbios_version,compute_cap,memory.total,memory.free,memory.used,temperature.gpu,power.limit,pstate,compute_mode,persistence_mode'
    output, status = _cuda_run(path, f'--query-gpu={fields}', '--format=csv,noheader,nounits')
    header, _ = _cuda_run(path)
    if header:
        match = re.search('CUDA(?:\\s+UMD)?\\s+Version:\\s*([\\d.]+)', header)
        probe['cuda_version'] = match.group(1) if match else None
    if status != 0 or output is None:
        probe['status'] = f'nvidia-smi query failed (exit {status})'
        return (probe, [])
    devices: list[dict[str, Any]] = []
    for row in output.splitlines():
        values = [item.strip() for item in row.split(',')]
        if len(values) != len(fields.split(',')):
            continue
        item = dict(zip(fields.split(','), values))
        devices.append({'index': _cuda_integer(item['index']), 'name': item['name'], 'uuid': item['uuid'], 'pci_bus_id': item['pci.bus_id'], 'driver_version': item['driver_version'], 'vbios_version': item['vbios_version'], 'compute_capability': _cuda_none(item['compute_cap']), 'memory_total_mib': _cuda_integer(item['memory.total']), 'memory_free_mib': _cuda_integer(item['memory.free']), 'memory_used_mib': _cuda_integer(item['memory.used']), 'temperature_celsius': _cuda_integer(item['temperature.gpu']), 'power_limit_watts': _cuda_number(item['power.limit']), 'performance_state': _cuda_none(item['pstate']), 'compute_mode': _cuda_none(item['compute_mode']), 'persistence_mode': _cuda_none(item['persistence_mode'])})
    probe.update({'available': True, 'status': 'available', 'device_count': len(devices)})
    return (probe, devices)

def _cuda_none(value: str | None) -> str | None:
    return None if value is None or value.strip().upper() in {'N/A', '[NOT SUPPORTED]', ''} else value

def _cuda_integer(value: str | None) -> int | None:
    try:
        return int(value) if _cuda_none(value) is not None else None
    except (TypeError, ValueError):
        return None

def _cuda_number(value: str | None) -> float | None:
    try:
        return float(value) if _cuda_none(value) is not None else None
    except (TypeError, ValueError):
        return None

def _cuda_merge_devices(driver_devices: list[dict[str, Any]], smi_devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not driver_devices:
        return [{'index': item.get('index'), 'name': item.get('name'), 'driver_api': {}, 'nvidia_smi': item} for item in smi_devices]
    by_index = {item.get('index'): item for item in smi_devices}
    report: list[dict[str, Any]] = []
    for item in driver_devices:
        report.append({'index': item.get('index'), 'name': item.get('name'), 'compute_capability': item.get('compute_capability'), 'total_memory_bytes': item.get('total_memory_bytes'), 'driver_api': item.get('driver_api_limits', {}), 'nvidia_smi': by_index.pop(item.get('index'), {})})
    report.extend(({'index': item.get('index'), 'name': item.get('name'), 'driver_api': {}, 'nvidia_smi': item} for item in by_index.values()))
    return report

def _cuda_collect_cuda_info() -> dict[str, Any]:
    roots = _cuda_candidate_roots()
    driver, driver_devices = _cuda_driver_api()
    smi, smi_devices = _cuda_nvidia_smi()
    nvcc_path = shutil.which('nvcc')
    nvcc_output, nvcc_status = _cuda_run(nvcc_path, '--version') if nvcc_path else (None, None)
    match = re.search('release\\s+([\\d.]+).*?V([\\d.]+)', nvcc_output or '', re.S)
    compiler = {'available': bool(nvcc_path and nvcc_status == 0), 'path': nvcc_path, 'release': match.group(1) if match else None, 'build_version': match.group(2) if match else None, 'status': 'available' if nvcc_path and nvcc_status == 0 else 'nvcc not found' if not nvcc_path else f'nvcc failed (exit {nvcc_status})'}
    return {'schema_version': 1, 'platform': {'operating_system': platform.system(), 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'availability': {'cuda_driver_api': driver['available'], 'nvidia_smi': smi['available'], 'compiler': compiler['available'], 'detected': bool(driver['available'] or smi['available'])}, 'probes': {'cuda_driver_api': driver, 'nvidia_smi': smi, 'nvcc': compiler}, 'installations': {'environment': {name: os.environ.get(name) for name in ('CUDA_PATH', 'CUDA_HOME', 'CUDA_ROOT') if os.environ.get(name)}, 'candidate_roots': roots, 'runtime_libraries': _cuda_library_candidates(roots)}, 'driver': {'cuda_driver_version': driver.get('driver_version'), 'cuda_driver_version_raw': driver.get('driver_version_raw'), 'nvidia_smi_cuda_version': smi.get('cuda_version')}, 'devices': _cuda_merge_devices(driver_devices, smi_devices)}

def _cuda_human(report: dict[str, Any]) -> None:
    availability = report['availability']
    print('CUDA: ' + ('detected' if availability['detected'] else 'not detected'))
    print('Driver API: %s | nvidia-smi: %s | nvcc: %s' % (availability['cuda_driver_api'], availability['nvidia_smi'], availability['compiler']))
    print('Driver CUDA version: %s | nvidia-smi CUDA version: %s' % (report['driver']['cuda_driver_version'] or 'unknown', report['driver']['nvidia_smi_cuda_version'] or 'unknown'))
    for device in report['devices']:
        smi = device.get('nvidia_smi', {})
        print('GPU %s: %s | CC %s | memory %s MiB | SMs %s' % (device.get('index'), device.get('name') or 'unknown', device.get('compute_capability') or smi.get('compute_capability') or 'unknown', smi.get('memory_total_mib') or (device.get('total_memory_bytes') // (1024 * 1024) if device.get('total_memory_bytes') else 'unknown'), device.get('driver_api', {}).get('multiprocessor_count', 'unknown')))
    if not report['devices']:
        print('No CUDA devices were enumerated. See --json probes for the reason.')

def _cuda_main() -> int:
    parser = argparse.ArgumentParser(description='Report CUDA driver, toolkit, GPU capability, and configuration information.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _cuda_collect_cuda_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _cuda_human(report)
    return 0

# Embedded direct3d_info collector implementation.
def _direct3d_compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _direct3d_compact(item) for key, item in value.items() if item not in (None, '')}
    if isinstance(value, list):
        return [_direct3d_compact(item) for item in value]
    return value

def _direct3d_run_powershell(script: str) -> Any:
    executable = shutil.which('powershell') or shutil.which('pwsh')
    if not executable:
        return None
    try:
        completed = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-Command', script], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=True)
        return json.loads(completed.stdout) if completed.stdout.strip() else None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None

def _direct3d_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return [value] if isinstance(value, dict) else []

def _direct3d_windows_inventory() -> tuple[dict[str, Any], str]:
    script = "$ErrorActionPreference='Stop'\n$o=[ordered]@{}\n$o.adapters=@(Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,AdapterDACType,AdapterRAM,CurrentBitsPerPixel,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate,CurrentScanMode,CurrentVideoMode,DriverDate,DriverVersion,InfFilename,InstalledDisplayDrivers,MaxRefreshRate,MinRefreshRate,PNPDeviceID,Status,VideoArchitecture,VideoMemoryType,VideoModeDescription,VideoProcessor)\n$o.os=Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture\n$o.directx=@{}\n$keys=@('HKLM:\\SOFTWARE\\Microsoft\\DirectX','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\DirectX')\nforeach($key in $keys) { if(Test-Path $key) { $p=Get-ItemProperty -Path $key; $o.directx[$key]=[ordered]@{Version=$p.Version;InstalledVersion=$p.InstalledVersion} } }\n$o | ConvertTo-Json -Depth 5 -Compress"
    value = _direct3d_run_powershell(script)
    return (value, 'powershell_cim_and_directx_registry') if isinstance(value, dict) else ({}, 'unavailable')

def _direct3d_normalize_adapter(item: dict[str, Any]) -> dict[str, Any]:
    return _direct3d_compact({'name': item.get('Name'), 'vendor': item.get('AdapterCompatibility'), 'video_processor': item.get('VideoProcessor'), 'dac': item.get('AdapterDACType'), 'dedicated_memory_bytes': item.get('AdapterRAM'), 'memory_type': item.get('VideoMemoryType'), 'architecture': item.get('VideoArchitecture'), 'driver_version': item.get('DriverVersion'), 'driver_date': item.get('DriverDate'), 'driver_inf': item.get('InfFilename'), 'installed_driver_files': item.get('InstalledDisplayDrivers'), 'pnp_device_id': item.get('PNPDeviceID'), 'status': item.get('Status'), 'current_mode': {'description': item.get('VideoModeDescription') or item.get('CurrentVideoMode'), 'width': item.get('CurrentHorizontalResolution'), 'height': item.get('CurrentVerticalResolution'), 'bits_per_pixel': item.get('CurrentBitsPerPixel'), 'refresh_rate_hz': item.get('CurrentRefreshRate'), 'scan_mode': item.get('CurrentScanMode')}, 'advertised_refresh_range_hz': {'minimum': item.get('MinRefreshRate'), 'maximum': item.get('MaxRefreshRate')}})

def _direct3d_dxdiag_text() -> tuple[str | None, str | None]:
    """Ask the Windows diagnostics tool for a temporary text report.

    DxDiag has no stdout report mode.  Its output is written in a temporary
    file and always removed; this is the only probe that writes anything.
    """
    executable = shutil.which('dxdiag')
    if not executable:
        return (None, 'dxdiag_not_found')
    handle = tempfile.NamedTemporaryFile(prefix='direct3d_info_', suffix='.txt', delete=False)
    output = handle.name
    handle.close()
    try:
        completed = subprocess.run([executable, '/whql:off', '/t', output], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=50)
        if completed.returncode != 0 or not Path(output).exists():
            return (None, 'dxdiag_failed')
        return (Path(output).read_text(encoding='utf-8', errors='replace'), 'dxdiag_text_report')
    except (OSError, subprocess.TimeoutExpired):
        return (None, 'dxdiag_failed_or_timed_out')
    finally:
        try:
            Path(output).unlink(missing_ok=True)
        except OSError:
            pass
_direct3d_DXDIAG_FIELD = re.compile('^\\s*([^:]{1,80}):\\s*(.*?)\\s*$')

def _direct3d_parse_dxdiag(text: str) -> dict[str, Any]:
    """Keep DxDiag key/value evidence, including localized field names.

    Key names are intentionally preserved because DxDiag follows the Windows
    display language.  English aliases below are conveniences, not guesses.
    """
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        if re.fullmatch('\\s*-{5,}\\s*', lines[index]) and index + 2 < len(lines) and re.fullmatch('\\s*-{5,}\\s*', lines[index + 2]):
            title = lines[index + 1].strip()
            relevant = bool(re.search('display|system information|directx files|diagnostics', title, re.IGNORECASE))
            current = title if title and relevant else None
            if current:
                sections.setdefault(current, {})
            index += 3
            continue
        field = _direct3d_DXDIAG_FIELD.match(lines[index])
        if current and field:
            key, value = field.groups()
            old = sections[current].get(key)
            sections[current][key] = value if old is None else old + ' | ' + value
        index += 1
    feature_levels: list[str] = []
    directx_version = None
    for fields in sections.values():
        for key, value in fields.items():
            low = key.lower()
            if 'feature level' in low:
                feature_levels.extend(re.findall('\\b(?:\\d+_\\d+|\\d+\\.\\d+)\\b', value))
            if directx_version is None and 'directx version' in low:
                directx_version = value
    return {'directx_version': directx_version, 'feature_levels': list(dict.fromkeys(feature_levels)), 'sections': sections}

def _direct3d_collect_direct3d_info(skip_dxdiag: bool=False) -> dict[str, Any]:
    """Collect a stable Direct3D report; no renderer or test device is created."""
    windows = sys.platform == 'win32'
    report: dict[str, Any] = {'platform': {'operating_system': platform.system(), 'release': platform.release(), 'machine': platform.machine()}, 'direct3d': {'supported_platform': windows, 'availability': 'not_applicable' if not windows else 'unknown', 'runtime': {'registry': {}, 'dxdiag_version': None}, 'adapters': [], 'feature_levels': [], 'dxdiag': {'attempted': False, 'source': None, 'sections': {}}, 'limitations': []}}
    d3d = report['direct3d']
    if not windows:
        d3d['limitations'].append('Direct3D is a Windows API; no compatibility layer is probed on this platform.')
        return report
    inventory, source = _direct3d_windows_inventory()
    d3d['adapters'] = [_direct3d_normalize_adapter(item) for item in _direct3d_list(inventory.get('adapters'))]
    d3d['runtime']['registry'] = inventory.get('directx') or {}
    d3d['operating_system'] = inventory.get('os') or {}
    if source == 'unavailable':
        d3d['limitations'].append('PowerShell/CIM inventory was unavailable or denied.')
    else:
        d3d['availability'] = 'runtime_registry_or_adapter_inventory_exposed' if d3d['adapters'] or d3d['runtime']['registry'] else 'unknown'
    if skip_dxdiag:
        d3d['limitations'].append('DxDiag was skipped; exact feature levels were not queried.')
        return report
    raw, dx_source = _direct3d_dxdiag_text()
    d3d['dxdiag']['attempted'] = True
    d3d['dxdiag']['source'] = dx_source
    if raw is None:
        d3d['limitations'].append('DxDiag did not provide a report; feature levels and diagnostics remain unreported.')
        return report
    parsed = _direct3d_parse_dxdiag(raw)
    d3d['runtime']['dxdiag_version'] = parsed['directx_version']
    d3d['feature_levels'] = parsed['feature_levels']
    d3d['dxdiag']['sections'] = parsed['sections']
    if parsed['feature_levels']:
        d3d['availability'] = 'feature_levels_reported_by_dxdiag'
    else:
        d3d['limitations'].append('DxDiag report contained no parseable feature-level field (it may be localized or unavailable).')
    return _direct3d_compact(report)

def _direct3d_print_human(report: dict[str, Any]) -> None:
    d3d = report['direct3d']
    print('Direct3D: %s' % d3d['availability'])
    print('Platform supported: %s' % d3d['supported_platform'])
    print('Adapters (%d): %s' % (len(d3d.get('adapters', [])), '; '.join((str(x.get('name', 'unknown')) for x in d3d.get('adapters', []))) or 'not reported'))
    print('Feature levels: %s' % (', '.join(d3d.get('feature_levels', [])) or 'not reported'))
    print('DxDiag: %s' % d3d['dxdiag'].get('source', 'not attempted'))
    for limitation in d3d.get('limitations', []):
        print('Note: %s' % limitation)

def _direct3d_main() -> int:
    parser = argparse.ArgumentParser(description='Report Windows Direct3D runtime, adapter, driver, and DxDiag information.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON report')
    parser.add_argument('--skip-dxdiag', action='store_true', help='do not launch DxDiag or create its temporary report')
    args = parser.parse_args()
    report = _direct3d_collect_direct3d_info(skip_dxdiag=args.skip_dxdiag)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _direct3d_print_human(report)
    return 0

# Embedded metal_info collector implementation.
def _metal_run(command: list[str], timeout: int=40) -> tuple[str | None, str | None]:
    if not shutil.which(command[0]):
        return (None, 'not installed or not on PATH')
    try:
        return (subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=timeout), None)
    except subprocess.TimeoutExpired:
        return (None, 'timed out')
    except (OSError, subprocess.CalledProcessError) as error:
        return (None, str(error))

def _metal_tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return {'found': bool(path), 'path': path}

def _metal_clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _metal_clean(item) for key, item in value.items() if item not in (None, '')}
    if isinstance(value, list):
        return [_metal_clean(item) for item in value]
    return value

def _metal_parse_profiler(text: str) -> tuple[dict[str, Any], str | None]:
    try:
        groups = plistlib.loads(text.encode('utf-8'))
    except (ValueError, TypeError) as error:
        return ({}, 'system_profiler XML could not be parsed: %s' % error)
    if not isinstance(groups, list):
        return ({}, 'system_profiler returned an unexpected XML shape')
    return ({str(group.get('_dataType')): group.get('_items', []) for group in groups if isinstance(group, dict)}, None)

def _metal_metal_fields(item: Any, path: str='') -> list[dict[str, Any]]:
    """Expose profiler fields that explicitly mention Metal or GPU families."""
    results: list[dict[str, Any]] = []
    if isinstance(item, dict):
        for key, value in item.items():
            current = path + '.' + key if path else key
            if re.search('metal|gpu.?family|feature.?set', key, re.I):
                results.append({'path': current, 'value': value})
            results.extend(_metal_metal_fields(value, current))
    elif isinstance(item, list):
        for index, value in enumerate(item):
            results.extend(_metal_metal_fields(value, '%s[%d]' % (path, index)))
    return results

def _metal_version(command: list[str]) -> str | None:
    output, _ = _metal_run(command, timeout=15)
    return output.strip() if output else None

def _metal_collect_metal_info() -> dict[str, Any]:
    system = platform.system()
    tools = {'system_profiler': _metal_tool('system_profiler'), 'xcrun': _metal_tool('xcrun'), 'xcodebuild': _metal_tool('xcodebuild')}
    probes: list[dict[str, Any]] = []
    limitations: list[str] = []
    devices: list[Any] = []
    details: dict[str, Any] = {}
    toolchain: dict[str, Any] = {}
    available: bool | None = False
    if system != 'Darwin':
        limitations.append('Metal is an Apple platform API and is not natively available on this operating system.')
    else:
        raw, error = _metal_run(['system_profiler', 'SPDisplaysDataType', 'SPHardwareDataType', 'SPSoftwareDataType', '-xml'])
        probes.append({'command': ['system_profiler', 'SPDisplaysDataType', 'SPHardwareDataType', 'SPSoftwareDataType', '-xml'], 'status': 'ok' if raw else 'unavailable', 'error': error})
        if raw:
            profiler, parse_error = _metal_parse_profiler(raw)
            if parse_error:
                limitations.append(parse_error)
            else:
                devices = profiler.get('SPDisplaysDataType', []) or []
                details['system_profiler'] = profiler
                details['metal_related_fields'] = _metal_metal_fields(devices)
                details['display_adapter_inventory_available'] = bool(devices)
                available = None
        else:
            available = None
            limitations.append('system_profiler could not enumerate display hardware; inspect the probe error.')
        if tools['xcrun']['found']:
            path, path_error = _metal_run(['xcrun', '--find', 'metal'], timeout=15)
            probes.append({'command': ['xcrun', '--find', 'metal'], 'status': 'ok' if path else 'unavailable', 'error': path_error})
            toolchain['metal_compiler_path'] = path.strip() if path else None
            version, version_error = _metal_run(['xcrun', 'metal', '-v'], timeout=15)
            probes.append({'command': ['xcrun', 'metal', '-v'], 'status': 'ok' if version else 'unavailable', 'error': version_error})
            toolchain['metal_compiler_version'] = version.strip() if version else None
        if tools['xcodebuild']['found']:
            toolchain['xcode_version'] = _metal_version(['xcodebuild', '-version'])
        limitations.append('system_profiler inventories display adapters, not native MTLDevice creation. This tool leaves Metal availability unknown unless a future native Metal probe confirms it; query a native Metal program for exact support and capabilities.')
    info = _metal_clean({'available': available, 'tools': tools, 'toolchain': toolchain, 'devices': devices, 'details': details, 'probes': probes, 'limitations': limitations})
    info['available'] = available
    return {'platform': {'operating_system': system, 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'metal': info}

def _metal_print_human(report: dict[str, Any]) -> None:
    info = report['metal']
    names: list[str] = []
    for device in info['devices']:
        if isinstance(device, dict):
            names.append(str(device.get('sppci_model') or device.get('_name') or device.get('spdisplays_vendor') or 'unknown display adapter'))
    print('Metal available: %s' % ('yes' if info.get('available') else 'no' if info.get('available') is False else 'not confirmed'))
    print('Display adapters (%d): %s' % (len(info['devices']), '; '.join(names[:4]) or 'not discovered'))
    print('Metal compiler: %s' % info['toolchain'].get('metal_compiler_version', 'not discovered'))
    fields = info['details'].get('metal_related_fields', [])
    print('Metal-related profiler fields: %d' % len(fields))
    for limitation in info['limitations']:
        print('Note: ' + limitation)

def _metal_main() -> int:
    parser = argparse.ArgumentParser(description='Report a read-only macOS Metal device, toolchain, and capability inventory.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _metal_collect_metal_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _metal_print_human(report)
    return 0

# Embedded nvidia_info collector implementation.
_nvidia_NVIDIA_PCI_VENDOR_ID = 4318
_nvidia_NVIDIA_SMI_FIELDS = 'index,name,uuid,pci.bus_id,driver_version'

class _nvidia_NvmlPciInfo(ctypes.Structure):
    """NVML's v2/v3-compatible PCI structure (the trailing busId is v2+)."""
    _fields_ = [('busIdLegacy', ctypes.c_char * 16), ('domain', ctypes.c_uint), ('bus', ctypes.c_uint), ('device', ctypes.c_uint), ('pciDeviceId', ctypes.c_uint), ('pciSubSystemId', ctypes.c_uint), ('busId', ctypes.c_char * 32)]

def _nvidia_run(*command: str, timeout: int=20) -> tuple[str | None, str | None]:
    """Run an optional read-only probe and retain a concise failure reason."""
    if not command or not command[0] or (not shutil.which(command[0])):
        return (None, 'not_found')
    try:
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return (None, 'timed_out')
    except OSError as error:
        return (None, type(error).__name__)
    if completed.returncode:
        return (None, 'exit_%d' % completed.returncode)
    return (completed.stdout, None)

def _nvidia_int(value: Any) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None

def _nvidia_version(raw: int | None) -> str | None:
    if raw is None:
        return None
    return '%d.%d' % (raw // 1000, raw % 1000 // 10) if raw >= 1000 else str(raw)

def _nvidia_clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _nvidia_clean(item) for key, item in value.items() if item not in (None, '')}
    if isinstance(value, list):
        return [_nvidia_clean(item) for item in value]
    return value

def _nvidia_load_cuda() -> tuple[Any | None, str | None]:
    names = ['nvcuda.dll'] if sys.platform == 'win32' else ['libcuda.so.1', 'libcuda.so']
    located = ctypes.util.find_library('cuda')
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == 'win32' else ctypes.CDLL
    for name in dict.fromkeys(names):
        try:
            return (loader(name), name)
        except OSError:
            pass
    return (None, None)

def _nvidia_cuda_driver() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe: dict[str, Any] = {'available': False, 'library': None, 'status': 'CUDA Driver API library was not found', 'driver_version': None}
    library, library_name = _nvidia_load_cuda()
    probe['library'] = library_name
    if library is None:
        return (probe, [])
    try:
        library.cuInit.argtypes, library.cuInit.restype = ([ctypes.c_uint], ctypes.c_int)
        result = library.cuInit(0)
        if result != 0:
            probe['status'] = 'cuInit failed with CUDA result %d' % result
            return (probe, [])
        library.cuDriverGetVersion.argtypes, library.cuDriverGetVersion.restype = ([ctypes.POINTER(ctypes.c_int)], ctypes.c_int)
        raw_version = ctypes.c_int()
        if library.cuDriverGetVersion(ctypes.byref(raw_version)) == 0:
            probe['driver_version'] = _nvidia_version(raw_version.value)
            probe['driver_version_raw'] = raw_version.value
        library.cuDeviceGetCount.argtypes, library.cuDeviceGetCount.restype = ([ctypes.POINTER(ctypes.c_int)], ctypes.c_int)
        count = ctypes.c_int()
        if library.cuDeviceGetCount(ctypes.byref(count)) != 0:
            probe['status'] = 'CUDA driver initialized but device enumeration failed'
            return (probe, [])
        library.cuDeviceGet.argtypes, library.cuDeviceGet.restype = ([ctypes.POINTER(ctypes.c_int), ctypes.c_int], ctypes.c_int)
        library.cuDeviceGetName.argtypes, library.cuDeviceGetName.restype = ([ctypes.c_char_p, ctypes.c_int, ctypes.c_int], ctypes.c_int)
        library.cuDeviceComputeCapability.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.c_int]
        library.cuDeviceComputeCapability.restype = ctypes.c_int
        get_uuid = getattr(library, 'cuDeviceGetUuid_v2', None) or getattr(library, 'cuDeviceGetUuid', None)
        if get_uuid:
            get_uuid.argtypes, get_uuid.restype = ([ctypes.c_void_p, ctypes.c_int], ctypes.c_int)
        get_pci_bus_id = getattr(library, 'cuDeviceGetPCIBusId', None)
        if get_pci_bus_id:
            get_pci_bus_id.argtypes, get_pci_bus_id.restype = ([ctypes.c_char_p, ctypes.c_int, ctypes.c_int], ctypes.c_int)
        devices: list[dict[str, Any]] = []
        for index in range(count.value):
            device, major, minor = (ctypes.c_int(), ctypes.c_int(), ctypes.c_int())
            if library.cuDeviceGet(ctypes.byref(device), index) != 0:
                continue
            name = ctypes.create_string_buffer(256)
            library.cuDeviceGetName(name, len(name), device.value)
            capability = None
            if library.cuDeviceComputeCapability(ctypes.byref(major), ctypes.byref(minor), device.value) == 0:
                capability = '%d.%d' % (major.value, minor.value)
            uuid = None
            if get_uuid:
                uuid_bytes = (ctypes.c_ubyte * 16)()
                if get_uuid(ctypes.byref(uuid_bytes), device.value) == 0:
                    raw_uuid = bytes(uuid_bytes).hex()
                    uuid = 'GPU-%s-%s-%s-%s-%s' % (raw_uuid[:8], raw_uuid[8:12], raw_uuid[12:16], raw_uuid[16:20], raw_uuid[20:])
            pci_bus_id = None
            if get_pci_bus_id:
                pci = ctypes.create_string_buffer(32)
                if get_pci_bus_id(pci, len(pci), device.value) == 0:
                    pci_bus_id = pci.value.decode(errors='replace') or None
            devices.append({'index': index, 'name': name.value.decode(errors='replace') or None, 'compute_capability': capability, 'uuid': uuid, 'pci_bus_id': pci_bus_id})
        probe.update({'available': True, 'status': 'available', 'device_count': len(devices)})
        return (probe, devices)
    except (AttributeError, OSError, ValueError) as error:
        probe['status'] = 'CUDA Driver API probe failed: %s' % type(error).__name__
        return (probe, [])

def _nvidia_nvidia_smi() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = shutil.which('nvidia-smi')
    probe: dict[str, Any] = {'available': False, 'path': path, 'status': 'nvidia-smi was not found', 'driver_version': None}
    if not path:
        return (probe, [])
    output, error = _nvidia_run(path, '--query-gpu=' + _nvidia_NVIDIA_SMI_FIELDS, '--format=csv,noheader,nounits')
    header, _ = _nvidia_run(path)
    if header:
        match = re.search('(?:Driver|KMD) Version:\\s*([^\\s]+)', header)
        probe['driver_version'] = match.group(1) if match else None
    if output is None:
        probe['status'] = 'nvidia-smi query failed: %s' % error
        return (probe, [])
    fields = _nvidia_NVIDIA_SMI_FIELDS.split(',')
    devices: list[dict[str, Any]] = []
    for row in output.splitlines():
        values = [value.strip() for value in row.split(',')]
        if len(values) != len(fields):
            continue
        item = dict(zip(fields, values))
        devices.append({'index': _nvidia_int(item['index']), 'name': item['name'] or None, 'uuid': item['uuid'] or None, 'pci_bus_id': item['pci.bus_id'] or None, 'driver_version': item['driver_version'] or None})
    probe.update({'available': True, 'status': 'available', 'device_count': len(devices)})
    return (probe, devices)

def _nvidia_load_nvml() -> tuple[Any | None, str | None]:
    names = ['nvml.dll'] if sys.platform == 'win32' else ['libnvidia-ml.so.1', 'libnvidia-ml.so']
    located = ctypes.util.find_library('nvidia-ml')
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == 'win32' else ctypes.CDLL
    for name in dict.fromkeys(names):
        try:
            return (loader(name), name)
        except OSError:
            pass
    return (None, None)

def _nvidia_nvml() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Use NVML capacity APIs, rather than guessing codec support from a SKU."""
    probe: dict[str, Any] = {'available': False, 'library': None, 'status': 'NVML library was not found', 'driver_version': None}
    library, library_name = _nvidia_load_nvml()
    probe['library'] = library_name
    if library is None:
        return (probe, {})
    try:
        initialize = getattr(library, 'nvmlInit_v2', None) or library.nvmlInit
        initialize.restype = ctypes.c_int
        result = initialize()
        if result != 0:
            probe['status'] = 'NVML initialization failed with result %d' % result
            return (probe, {})
        try:
            driver = ctypes.create_string_buffer(80)
            get_driver = getattr(library, 'nvmlSystemGetDriverVersion')
            get_driver.argtypes, get_driver.restype = ([ctypes.c_char_p, ctypes.c_uint], ctypes.c_int)
            if get_driver(driver, len(driver)) == 0:
                probe['driver_version'] = driver.value.decode(errors='replace')
            count = ctypes.c_uint()
            get_count = getattr(library, 'nvmlDeviceGetCount_v2', None) or library.nvmlDeviceGetCount
            get_count.argtypes, get_count.restype = ([ctypes.POINTER(ctypes.c_uint)], ctypes.c_int)
            if get_count(ctypes.byref(count)) != 0:
                probe['status'] = 'NVML initialized but device enumeration failed'
                return (probe, {})
            get_handle = getattr(library, 'nvmlDeviceGetHandleByIndex_v2', None) or library.nvmlDeviceGetHandleByIndex
            get_handle.argtypes, get_handle.restype = ([ctypes.c_uint, ctypes.POINTER(ctypes.c_void_p)], ctypes.c_int)
            get_uuid = getattr(library, 'nvmlDeviceGetUUID', None)
            if get_uuid:
                get_uuid.argtypes, get_uuid.restype = ([ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint], ctypes.c_int)
            get_name = getattr(library, 'nvmlDeviceGetName', None)
            if get_name:
                get_name.argtypes, get_name.restype = ([ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint], ctypes.c_int)
            get_pci = getattr(library, 'nvmlDeviceGetPciInfo_v3', None) or getattr(library, 'nvmlDeviceGetPciInfo_v2', None)
            if get_pci:
                get_pci.argtypes, get_pci.restype = ([ctypes.c_void_p, ctypes.POINTER(_nvidia_NvmlPciInfo)], ctypes.c_int)
            devices: list[dict[str, Any]] = []
            for index in range(count.value):
                handle = ctypes.c_void_p()
                if get_handle(index, ctypes.byref(handle)) != 0:
                    continue
                decoder = _nvidia_codec_capacities(library, 'nvmlDeviceGetDecoderCapacity', handle)
                decoder['utilization'] = _nvidia_decoder_utilization(library, handle)
                uuid_buffer, name_buffer = (ctypes.create_string_buffer(96), ctypes.create_string_buffer(96))
                uuid = uuid_buffer.value.decode(errors='replace') if get_uuid and get_uuid(handle, uuid_buffer, len(uuid_buffer)) == 0 else None
                name = name_buffer.value.decode(errors='replace') if get_name and get_name(handle, name_buffer, len(name_buffer)) == 0 else None
                pci_info = _nvidia_NvmlPciInfo()
                pci_bus_id = pci_info.busId.split(b'\x00', 1)[0].decode(errors='replace') if get_pci and get_pci(handle, ctypes.byref(pci_info)) == 0 else None
                devices.append({'index': index, 'uuid': uuid, 'pci_bus_id': pci_bus_id, 'name': name, 'codec_capabilities': {'nvenc': _nvidia_codec_capacities(library, 'nvmlDeviceGetEncoderCapacity', handle), 'nvdec': decoder}})
            probe.update({'available': True, 'status': 'available', 'device_count': count.value})
            return (probe, devices)
        finally:
            shutdown = getattr(library, 'nvmlShutdown', None)
            if shutdown:
                shutdown()
    except (AttributeError, OSError, ValueError) as error:
        probe['status'] = 'NVML probe failed: %s' % type(error).__name__
        return (probe, {})

def _nvidia_codec_capacities(library: Any, function_name: str, handle: ctypes.c_void_p) -> dict[str, Any]:
    function = getattr(library, function_name, None)
    if function is None:
        return {'api_available': False, 'status': 'capacity_api_not_exported', 'codecs': {}}
    function.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint)]
    function.restype = ctypes.c_int
    codecs: dict[str, Any] = {}
    for name, query_type in (('h264', 0), ('hevc', 1), ('av1', 2)):
        capacity = ctypes.c_uint()
        result = function(handle, query_type, ctypes.byref(capacity))
        codecs[name] = {'nvml_result': result, 'capacity_percent': capacity.value if result == 0 else None}
    successes = [item for item in codecs.values() if item['nvml_result'] == 0]
    return {'api_available': True, 'status': 'available' if successes else 'no_successful_codec_query', 'codecs': codecs}

def _nvidia_decoder_utilization(library: Any, handle: ctypes.c_void_p) -> dict[str, Any]:
    """NVML exposes this more widely than decoder codec-capacity queries."""
    function = getattr(library, 'nvmlDeviceGetDecoderUtilization', None)
    if function is None:
        return {'api_available': False, 'status': 'utilization_api_not_exported'}
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
    function.restype = ctypes.c_int
    utilization, period = (ctypes.c_uint(), ctypes.c_uint())
    result = function(handle, ctypes.byref(utilization), ctypes.byref(period))
    return {'api_available': True, 'nvml_result': result, 'utilization_percent': utilization.value if result == 0 else None, 'sampling_period_microseconds': period.value if result == 0 else None}

def _nvidia_os_inventory() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    system = platform.system()
    if system == 'Windows':
        command = 'Get-CimInstance Win32_VideoController | Select-Object Name,AdapterCompatibility,DriverVersion,PNPDeviceID | ConvertTo-Json -Compress'
        raw, error = _nvidia_run(shutil.which('powershell') or shutil.which('pwsh') or '', '-NoProfile', '-NonInteractive', '-Command', command)
        try:
            rows = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            rows = []
        rows = rows if isinstance(rows, list) else [rows] if isinstance(rows, dict) else []
        devices = [{'name': row.get('Name'), 'driver_version': row.get('DriverVersion'), 'pnp_device_id': row.get('PNPDeviceID')} for row in rows if 'nvidia' in (str(row.get('AdapterCompatibility')) + str(row.get('Name'))).lower()]
        return ({'available': raw is not None, 'source': 'windows_cim', 'status': 'available' if raw is not None else error}, devices)
    if system == 'Linux':
        raw, error = _nvidia_run('lspci', '-mm', '-nn')
        devices = []
        for line in (raw or '').splitlines():
            if 'nvidia' in line.lower() or '[10de:' in line.lower():
                devices.append({'name': line, 'pci_record': line})
        return ({'available': raw is not None, 'source': 'lspci', 'status': 'available' if raw is not None else error}, devices)
    return ({'available': False, 'source': None, 'status': 'no_supported_os_fallback'}, [])

def _nvidia_collect_vk_extensions(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.startswith('VK_'):
                found.add(key)
            if isinstance(key, str) and 'extensionname' in key.lower() and isinstance(item, str) and item.startswith('VK_'):
                found.add(item)
            found.update(_nvidia_collect_vk_extensions(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_nvidia_collect_vk_extensions(item))
    return found

def _nvidia_vulkan() -> dict[str, Any]:
    executable = shutil.which('vulkaninfo')
    probe: dict[str, Any] = {'available': False, 'path': executable, 'status': 'vulkaninfo was not found', 'nvidia_device_extensions': {}}
    if not executable:
        return probe
    try:
        with tempfile.TemporaryDirectory(prefix='nvidia-info-') as directory:
            completed = subprocess.run([executable, '--json'], cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            if completed.returncode != 0:
                probe['status'] = 'vulkaninfo --json failed: exit_%d' % completed.returncode
                return probe
            generated = list(Path(directory).glob('VP_VULKANINFO_*.json'))
            if generated:
                raw = generated[0].read_text(encoding='utf-8', errors='replace')
            else:
                raw = completed.stdout
            if not raw.strip():
                probe['status'] = 'vulkaninfo --json emitted no report'
                return probe
            document = json.loads(raw)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        probe['status'] = 'vulkaninfo JSON probe failed: %s' % type(error).__name__
        return probe
    scopes: list[dict[str, Any]] = []

    def visit(item: Any) -> None:
        if isinstance(item, dict):
            vendor = next((_nvidia_int(item.get(key)) for key in ('vendorID', 'vendorId', 'vendor_id') if _nvidia_int(item.get(key)) is not None), None)
            name = next((item.get(key) for key in ('deviceName', 'device_name') if item.get(key)), None)
            if vendor == _nvidia_NVIDIA_PCI_VENDOR_ID:
                extensions = _nvidia_collect_vk_extensions(item)
                if extensions:
                    scopes.append({'name': name, 'extensions': sorted(extensions)})
                return
            for child in item.values():
                visit(child)
        elif isinstance(item, list):
            for child in item:
                visit(child)
    visit(document)
    profile_device = document.get('capabilities', {}).get('device', {}) if isinstance(document, dict) else {}
    profile_extensions = set((profile_device.get('extensions') or {}).keys()) if isinstance(profile_device, dict) else set()
    properties = profile_device.get('properties', {}) if isinstance(profile_device, dict) else {}
    core_properties = properties.get('VkPhysicalDeviceProperties', {}) if isinstance(properties, dict) else {}
    profile_vendor = _nvidia_int(core_properties.get('vendorID')) if isinstance(core_properties, dict) else None
    if profile_vendor == _nvidia_NVIDIA_PCI_VENDOR_ID and profile_extensions:
        scopes.append({'name': core_properties.get('deviceName'), 'extensions': sorted(profile_extensions)})
    probe.update({'available': True, 'status': 'available', 'nvidia_device_extensions': {str(index): scope for index, scope in enumerate(scopes)}})
    if not scopes:
        probe['status'] = 'available; JSON schema did not expose a scoped NVIDIA physical-device record'
    return probe

def _nvidia_ngx_components() -> dict[str, Any]:
    names = {'dlss_super_resolution': ('nvngx_dlss.dll', 'libnvidia-ngx-dlss.so', 'libnvidia-ngx-dlss.so.1'), 'dlss_frame_generation': ('nvngx_dlssg.dll', 'libnvidia-ngx-dlssg.so', 'libnvidia-ngx-dlssg.so.1'), 'dlss_ray_reconstruction': ('nvngx_dlssd.dll', 'libnvidia-ngx-dlssd.so', 'libnvidia-ngx-dlssd.so.1')}
    roots = [Path(path) for path in os.environ.get('PATH', '').split(os.pathsep) if path]
    if sys.platform == 'win32':
        roots.append(Path(os.environ.get('SystemRoot', 'C:\\\\Windows')) / 'System32')
    found: dict[str, list[str]] = {}
    for feature, candidates in names.items():
        found[feature] = [str(root / candidate) for root in roots for candidate in candidates if (root / candidate).is_file()]
    return {'searched_paths': len(roots), 'components': found}

def _nvidia_feature(detection: str='unknown', support: str='unknown', eligibility: str='unknown', evidence: list[dict[str, Any]] | None=None, limitation: str | None=None) -> dict[str, Any]:
    result = {'detection': detection, 'support': support, 'eligibility': eligibility, 'evidence': evidence or []}
    if limitation:
        result['limitations'] = [limitation]
    return result

def _nvidia_cc_number(device: dict[str, Any]) -> float | None:
    try:
        return float(str(device.get('compute_capability')))
    except (TypeError, ValueError):
        return None

def _nvidia_capabilities(device: dict[str, Any], nvml: dict[str, Any], vulkan_extensions: set[str], ngx: dict[str, Any]) -> dict[str, Any]:
    cc = _nvidia_cc_number(device)
    compute_evidence = [{'source': 'cuda_driver_api', 'fact': 'compute_capability', 'value': device.get('compute_capability')}] if cc is not None else []
    caps: dict[str, Any] = {}
    for feature in ('dlss_super_resolution', 'dlss_frame_generation', 'dlss_ray_reconstruction'):
        files = ngx['components'].get(feature, [])
        caps[feature] = _nvidia_feature('detected' if files else 'unknown', 'unknown', 'unknown', [{'source': 'local_ngx_component', 'paths': files}] if files else [], 'DLSS support is negotiated by NGX in an application; neither a GPU name nor a driver version confirms it.')
    reflex_extensions = {'VK_NV_low_latency', 'VK_NV_low_latency2'}
    reflex = sorted(vulkan_extensions & reflex_extensions)
    caps['reflex'] = _nvidia_feature('detected' if reflex else 'unknown', 'unknown', 'unknown', [{'source': 'vulkaninfo', 'extensions': reflex}] if reflex else [], 'A Vulkan low-latency extension is evidence of a driver interface, not proof that NVIDIA Reflex SDK integration will initialize in a game.')
    ray_extensions = {'VK_KHR_acceleration_structure', 'VK_KHR_ray_tracing_pipeline'}
    ray = sorted(vulkan_extensions & ray_extensions)
    caps['rtx_ray_tracing'] = _nvidia_feature('detected' if len(ray) == len(ray_extensions) else 'unknown', 'supported' if len(ray) == len(ray_extensions) else 'unknown', 'unknown', [{'source': 'vulkaninfo', 'extensions': ray}] if ray else [], 'Requires both Vulkan ray-tracing extensions in a NVIDIA physical-device scope; CUDA compute capability alone does not prove RT-core availability.')
    tensor_eligible = cc is not None and cc >= 7.0
    caps['tensor_cores'] = _nvidia_feature('unknown', 'unknown', 'likely_eligible_by_architecture' if tensor_eligible else 'unknown', compute_evidence, 'CUDA reports compute capability, not a direct Tensor Core feature bit. Eligibility is not a workload or library support test.')
    for feature in ('nvenc', 'nvdec'):
        capacity = nvml.get(feature) or {'api_available': False, 'status': 'not_queried', 'codecs': {}}
        successful = [name for name, result in capacity.get('codecs', {}).items() if result.get('nvml_result') == 0]
        unsupported = [result for result in capacity.get('codecs', {}).values() if result.get('nvml_result') == 3]
        decoder_utilization = capacity.get('utilization', {}) if feature == 'nvdec' else {}
        decoder_available = decoder_utilization.get('nvml_result') == 0
        support = 'supported' if successful else 'not_supported' if unsupported and len(unsupported) == len(capacity.get('codecs', {})) else 'unknown'
        caps[feature] = _nvidia_feature('detected' if successful or decoder_available else 'unknown', support, 'unknown', [{'source': 'nvml_%s_capacity' % feature, 'result': capacity}], 'NVML capacity calls are direct codec-support evidence. Decoder utilization only detects a usable activity interface; it does not identify supported codecs. An unsupported or invalid codec enum on an older driver does not prove that the GPU lacks the engine.')
    return caps

def _nvidia_vulkan_extensions_for(device: dict[str, Any], vulkan: dict[str, Any]) -> set[str]:
    name = str(device.get('name') or '').casefold()
    matches: set[str] = set()
    for scope in vulkan.get('nvidia_device_extensions', {}).values():
        scope_name = str(scope.get('name') or '').casefold()
        if name and scope_name and (name == scope_name or name in scope_name or scope_name in name):
            matches.update(scope.get('extensions') or [])
    return matches

def _nvidia_normalized_pci_bus_id(value: Any) -> str | None:
    """Normalize NVIDIA's 00000000:01:00.0 and Vulkan-style BDF variants."""
    match = re.fullmatch('\\s*(?:(?:[0-9a-fA-F]{1,8}):)?([0-9a-fA-F]{1,2}):([0-9a-fA-F]{1,2})\\.([0-7])\\s*', str(value or ''))
    if not match:
        return None
    bus, device, function = match.groups()
    return '0000:%02x:%02x.%d' % (int(bus, 16), int(device, 16), int(function))

def _nvidia_find_identity_match(device: dict[str, Any], candidates: list[dict[str, Any]], used: set[int]) -> int | None:
    """Match UUID before PCI, refusing ambiguous PCI/MIG fallback matches."""
    uuid = str(device.get('uuid') or '').casefold()
    if uuid:
        matches = [index for index, candidate in enumerate(candidates) if index not in used and str(candidate.get('uuid') or '').casefold() == uuid]
        if len(matches) == 1:
            return matches[0]
        return None
    pci = _nvidia_normalized_pci_bus_id(device.get('pci_bus_id'))
    if pci:
        matches = [index for index, candidate in enumerate(candidates) if index not in used and _nvidia_normalized_pci_bus_id(candidate.get('pci_bus_id')) == pci]
        if len(matches) == 1:
            return matches[0]
    return None

def _nvidia_merge_devices(cuda: list[dict[str, Any]], smi: list[dict[str, Any]], os_devices: list[dict[str, Any]], nvml: list[dict[str, Any]], vulkan: dict[str, Any], ngx: dict[str, Any]) -> list[dict[str, Any]]:
    """Merge physical-device sources without assuming their ordinals agree.

    CUDA_VISIBLE_DEVICES, CUDA_DEVICE_ORDER, and MIG can make CUDA ordinal 0
    correspond to a different physical GPU (or compute instance) than ordinal
    0 in NVML/nvidia-smi. UUID is authoritative; PCI is only accepted when it
    identifies exactly one otherwise-unmatched record.
    """
    devices: list[dict[str, Any]] = []
    used_smi: set[int] = set()
    for item in cuda:
        smi_index = _nvidia_find_identity_match(item, smi, used_smi)
        smi_item = smi[smi_index] if smi_index is not None else {}
        if smi_index is not None:
            used_smi.add(smi_index)
        devices.append({'index': item.get('index'), 'name': item.get('name') or smi_item.get('name'), 'compute_capability': item.get('compute_capability'), 'uuid': item.get('uuid') or smi_item.get('uuid'), 'pci_bus_id': item.get('pci_bus_id') or smi_item.get('pci_bus_id'), 'driver_version': smi_item.get('driver_version'), 'sources': ['cuda_driver_api'] + (['nvidia_smi'] if smi_index is not None else [])})
    for index, item in enumerate(smi):
        if index not in used_smi:
            devices.append({'index': item.get('index'), 'name': item.get('name'), 'uuid': item.get('uuid'), 'pci_bus_id': item.get('pci_bus_id'), 'driver_version': item.get('driver_version'), 'sources': ['nvidia_smi']})
    used_nvml: set[int] = set()
    for device in devices:
        nvml_index = _nvidia_find_identity_match(device, nvml, used_nvml)
        if nvml_index is not None:
            used_nvml.add(nvml_index)
            device['nvml_capabilities'] = nvml[nvml_index].get('codec_capabilities', {})
            device['sources'].append('nvml')
    for index, item in enumerate(nvml):
        if index not in used_nvml:
            devices.append({'index': None, 'name': item.get('name'), 'uuid': item.get('uuid'), 'sources': ['nvml'], 'nvml_capabilities': item.get('codec_capabilities', {})})
    if not devices:
        for item in os_devices:
            devices.append({'index': None, 'name': item.get('name'), 'driver_version': item.get('driver_version'), 'sources': ['os_inventory'], 'os_evidence': item})
    for device in devices:
        device['capabilities'] = _nvidia_capabilities(device, device.pop('nvml_capabilities', {}), _nvidia_vulkan_extensions_for(device, vulkan), ngx)
    return [_nvidia_clean(device) for device in devices]

def _nvidia_collect_nvidia_info() -> dict[str, Any]:
    cuda_probe, cuda_devices = _nvidia_cuda_driver()
    smi_probe, smi_devices = _nvidia_nvidia_smi()
    nvml_probe, nvml_devices = _nvidia_nvml()
    os_probe, os_devices = _nvidia_os_inventory()
    vulkan_probe = _nvidia_vulkan()
    ngx_probe = _nvidia_ngx_components()
    devices = _nvidia_merge_devices(cuda_devices, smi_devices, os_devices, nvml_devices, vulkan_probe, ngx_probe)
    return {'schema_version': 1, 'platform': {'operating_system': platform.system(), 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'availability': {'nvidia_devices_detected': bool(devices), 'cuda_driver_api': cuda_probe['available'], 'nvidia_smi': smi_probe['available'], 'nvml': nvml_probe['available'], 'vulkaninfo': vulkan_probe['available']}, 'driver': {'cuda_driver_version': cuda_probe.get('driver_version'), 'nvidia_smi_driver_version': smi_probe.get('driver_version'), 'nvml_driver_version': nvml_probe.get('driver_version')}, 'probes': {'cuda_driver_api': cuda_probe, 'nvidia_smi': smi_probe, 'nvml': nvml_probe, 'os_inventory': os_probe, 'vulkan': vulkan_probe, 'ngx_components': ngx_probe}, 'devices': devices, 'limitations': ["Feature status is per enumerated device. 'detected' is direct local evidence, 'supported' means a queried API exposed the feature, and 'likely_eligible_by_architecture' is deliberately weaker than support.", 'DLSS and Reflex require an application/SDK initialization path. This read-only inventory does not start a renderer, NGX, encoder, decoder, or game.']}

def _nvidia_human(report: dict[str, Any]) -> None:
    available = report['availability']
    print('NVIDIA GPUs: %s' % ('detected' if available['nvidia_devices_detected'] else 'not detected'))
    print('CUDA Driver API: %s | NVML: %s | nvidia-smi: %s | Vulkan probe: %s' % (available['cuda_driver_api'], available['nvml'], available['nvidia_smi'], available['vulkaninfo']))
    for device in report['devices']:
        print('GPU %s: %s | compute capability %s | sources: %s' % (device.get('index', 'OS'), device.get('name', 'unknown'), device.get('compute_capability', 'unknown'), ', '.join(device.get('sources', []))))
        for feature, result in device.get('capabilities', {}).items():
            print('  %s: detection=%s, support=%s, eligibility=%s' % (feature, result['detection'], result['support'], result['eligibility']))
    if not report['devices']:
        print('No NVIDIA device was enumerated. Use --json to inspect every probe result.')

def _nvidia_main() -> int:
    parser = argparse.ArgumentParser(description='Report evidence-backed NVIDIA GPU, DLSS, Reflex, RTX, Tensor, NVENC, and NVDEC capability information.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _nvidia_collect_nvidia_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _nvidia_human(report)
    return 0

# Embedded opencl_info collector implementation.
_opencl_CL_SUCCESS = 0
_opencl_CL_DEVICE_TYPE_ALL = 4294967295
_opencl_CL_PLATFORM_NOT_FOUND_KHR = -1001
_opencl_PLATFORM_INFO = {'profile': 2304, 'version': 2305, 'name': 2306, 'vendor': 2307, 'extensions': 2308}
_opencl_STRING_PROPERTIES = {'name': 4139, 'vendor': 4140, 'driver_version': 4141, 'profile': 4142, 'device_version': 4143, 'extensions': 4144, 'opencl_c_version': 4157, 'built_in_kernels': 4159, 'il_version': 4187}
_opencl_UINT_PROPERTIES = {'vendor_id': 4097, 'max_compute_units': 4098, 'max_work_item_dimensions': 4099, 'preferred_vector_width_char': 4102, 'preferred_vector_width_short': 4103, 'preferred_vector_width_int': 4104, 'preferred_vector_width_long': 4105, 'preferred_vector_width_float': 4106, 'preferred_vector_width_double': 4107, 'max_clock_frequency_mhz': 4108, 'address_bits': 4109, 'max_read_image_args': 4110, 'max_write_image_args': 4111, 'max_samplers': 4120, 'mem_base_addr_align_bits': 4121, 'min_data_type_align_size': 4122, 'global_mem_cacheline_size': 4125, 'max_constant_args': 4129, 'local_mem_type': 4130, 'error_correction_support': 4132, 'profiling_timer_resolution_ns': 4133, 'endian_little': 4134, 'available': 4135, 'compiler_available': 4136, 'execution_capabilities': 4137, 'queue_properties': 4138, 'global_mem_cache_type': 4124, 'single_fp_config': 4123, 'double_fp_config': 4146, 'half_fp_config': 4147, 'preferred_interop_user_sync': 4168, 'partition_max_sub_devices': 4163, 'partition_affinity_domain': 4165}
_opencl_SIZE_PROPERTIES = {'max_work_group_size': 4100, 'max_mem_alloc_size_bytes': 4112, 'max_parameter_size_bytes': 4119, 'image2d_max_width': 4113, 'image2d_max_height': 4114, 'image3d_max_width': 4115, 'image3d_max_height': 4116, 'image3d_max_depth': 4117, 'max_global_variable_size_bytes': 4173, 'global_variable_preferred_total_size_bytes': 4180}
_opencl_ULONG_PROPERTIES = {'global_mem_cache_size_bytes': 4126, 'global_mem_size_bytes': 4127, 'max_constant_buffer_size_bytes': 4128, 'local_mem_size_bytes': 4131, 'printf_buffer_size_bytes': 4169, 'max_pipe_args': 4181, 'pipe_max_active_reservations': 4182, 'pipe_max_packet_size': 4183, 'svm_capabilities': 4179}

def _opencl_run(*command: str) -> tuple[str | None, int | None]:
    if not command or not shutil.which(command[0]):
        return (None, None)
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return (result.stdout, result.returncode)
    except (OSError, subprocess.TimeoutExpired):
        return (None, None)

def _opencl_load_opencl() -> tuple[Any | None, str | None]:
    names = ['OpenCL.dll'] if sys.platform == 'win32' else ['/System/Library/Frameworks/OpenCL.framework/OpenCL'] if sys.platform == 'darwin' else ['libOpenCL.so.1', 'libOpenCL.so']
    located = ctypes.util.find_library('OpenCL')
    if located:
        names.append(located)
    loader = ctypes.WinDLL if sys.platform == 'win32' else ctypes.CDLL
    for name in names:
        try:
            return (loader(name), name)
        except OSError:
            pass
    return (None, None)

def _opencl_string(getter: Any, handle: Any, code: int) -> str | None:
    size = ctypes.c_size_t()
    if getter(handle, code, 0, None, ctypes.byref(size)) != _opencl_CL_SUCCESS or not size.value:
        return None
    raw = ctypes.create_string_buffer(size.value)
    if getter(handle, code, size.value, raw, None) != _opencl_CL_SUCCESS:
        return None
    return raw.value.decode(errors='replace').strip() or None

def _opencl_bytes(getter: Any, handle: Any, code: int) -> bytes | None:
    size = ctypes.c_size_t()
    if getter(handle, code, 0, None, ctypes.byref(size)) != _opencl_CL_SUCCESS or not size.value:
        return None
    raw = (ctypes.c_ubyte * size.value)()
    return bytes(raw) if getter(handle, code, size.value, raw, None) == _opencl_CL_SUCCESS else None

def _opencl_int_property(getter: Any, handle: Any, code: int) -> int | None:
    value = _opencl_bytes(getter, handle, code)
    return int.from_bytes(value, byteorder=sys.byteorder, signed=False) if value else None

def _opencl_device_type(value: int | None) -> list[str]:
    labels = ((1, 'default'), (2, 'cpu'), (4, 'gpu'), (8, 'accelerator'), (16, 'custom'))
    return [name for bit, name in labels if value and value & bit]

def _opencl_split_extensions(value: str | None) -> list[str]:
    return sorted(value.split()) if value else []

def _opencl_split_builtins(value: str | None) -> list[str]:
    return [item.strip() for item in value.split(';') if item.strip()] if value else []

def _opencl_flags(value: int | None, definitions: dict[str, int]) -> list[str] | None:
    """Decode a bit field without treating an unsupported query as no flags."""
    return [name for name, bit in definitions.items() if value & bit] if value is not None else None

def _opencl_bool(value: int | None) -> bool | None:
    """Preserve an unavailable OpenCL property as unknown rather than false."""
    return None if value is None else bool(value)

def _opencl_opencl_api() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    probe = {'available': False, 'library': None, 'status': 'OpenCL loader was not found', 'platform_count': 0}
    library, name = _opencl_load_opencl()
    probe['library'] = name
    if library is None:
        return (probe, [])
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
        if result != _opencl_CL_SUCCESS:
            probe['status'] = 'no OpenCL platforms reported by installed loader' if result == _opencl_CL_PLATFORM_NOT_FOUND_KHR else f'clGetPlatformIDs failed with OpenCL result {result}'
            return (probe, [])
        platforms_raw = (ctypes.c_void_p * count.value)()
        if library.clGetPlatformIDs(count.value, platforms_raw, None) != _opencl_CL_SUCCESS:
            probe['status'] = 'OpenCL platform enumeration failed'
            return (probe, [])
        platforms: list[dict[str, Any]] = []
        for platform_id in platforms_raw:
            platform_data = {label: _opencl_string(library.clGetPlatformInfo, platform_id, code) for label, code in _opencl_PLATFORM_INFO.items()}
            platform_data['extensions'] = _opencl_split_extensions(platform_data['extensions'])
            device_count = ctypes.c_uint()
            device_result = library.clGetDeviceIDs(platform_id, _opencl_CL_DEVICE_TYPE_ALL, 0, None, ctypes.byref(device_count))
            devices: list[dict[str, Any]] = []
            if device_result == _opencl_CL_SUCCESS and device_count.value:
                device_ids = (ctypes.c_void_p * device_count.value)()
                if library.clGetDeviceIDs(platform_id, _opencl_CL_DEVICE_TYPE_ALL, device_count.value, device_ids, None) == _opencl_CL_SUCCESS:
                    devices = [_opencl_collect_device(library.clGetDeviceInfo, device_id) for device_id in device_ids]
            platform_data['device_query_result'] = device_result
            platform_data['devices'] = devices
            platforms.append(platform_data)
        probe.update({'available': True, 'status': 'available', 'platform_count': len(platforms)})
        return (probe, platforms)
    except (AttributeError, OSError, ValueError) as error:
        probe['status'] = f'OpenCL API probe failed: {type(error).__name__}'
        return (probe, [])

def _opencl_collect_device(getter: Any, device_id: Any) -> dict[str, Any]:
    strings = {label: _opencl_string(getter, device_id, code) for label, code in _opencl_STRING_PROPERTIES.items()}
    raw_type = _opencl_int_property(getter, device_id, 4096)
    numeric = {label: _opencl_int_property(getter, device_id, code) for label, code in _opencl_UINT_PROPERTIES.items()}
    numeric.update({label: _opencl_int_property(getter, device_id, code) for label, code in _opencl_SIZE_PROPERTIES.items()})
    numeric.update({label: _opencl_int_property(getter, device_id, code) for label, code in _opencl_ULONG_PROPERTIES.items()})
    dimensions = numeric.get('max_work_item_dimensions')
    work_sizes = _opencl_bytes(getter, device_id, 4101)
    size_width = ctypes.sizeof(ctypes.c_size_t)
    result: dict[str, Any] = {'name': strings['name'], 'vendor': strings['vendor'], 'device_type': _opencl_device_type(raw_type), 'profile': strings['profile'], 'device_version': strings['device_version'], 'driver_version': strings['driver_version'], 'opencl_c_version': strings['opencl_c_version'], 'il_version': strings['il_version'], 'extensions': _opencl_split_extensions(strings['extensions']), 'built_in_kernels': _opencl_split_builtins(strings['built_in_kernels']), 'limits': numeric, 'max_work_item_sizes': [int.from_bytes(work_sizes[index:index + size_width], sys.byteorder) for index in range(0, min(len(work_sizes or b''), (dimensions or 0) * size_width), size_width)] if work_sizes else []}
    result['features'] = {'image_support': _opencl_bool(_opencl_int_property(getter, device_id, 4118)), 'compiler_available': _opencl_bool(numeric.get('compiler_available')), 'linker_available': _opencl_bool(_opencl_int_property(getter, device_id, 4158)), 'error_correction': _opencl_bool(numeric.get('error_correction_support')), 'svm_capabilities': numeric.get('svm_capabilities'), 'svm_features': _opencl_flags(numeric.get('svm_capabilities'), {'coarse_grain_buffer': 1, 'fine_grain_buffer': 2, 'fine_grain_system': 4, 'atomics': 8}), 'execution_capabilities': numeric.get('execution_capabilities'), 'execution_features': _opencl_flags(numeric.get('execution_capabilities'), {'kernel': 1, 'native_kernel': 2}), 'queue_properties': numeric.get('queue_properties'), 'queue_features': _opencl_flags(numeric.get('queue_properties'), {'out_of_order': 1, 'profiling': 2}), 'single_fp_config': numeric.get('single_fp_config'), 'double_fp_config': numeric.get('double_fp_config'), 'half_fp_config': numeric.get('half_fp_config'), 'single_fp_features': _opencl_flags(numeric.get('single_fp_config'), {'denorm': 1, 'inf_nan': 2, 'round_to_nearest': 4, 'round_to_zero': 8, 'round_to_inf': 16, 'fma': 32, 'soft_float': 64, 'correctly_rounded_divide_sqrt': 128}), 'double_fp_features': _opencl_flags(numeric.get('double_fp_config'), {'denorm': 1, 'inf_nan': 2, 'round_to_nearest': 4, 'round_to_zero': 8, 'round_to_inf': 16, 'fma': 32, 'soft_float': 64, 'correctly_rounded_divide_sqrt': 128}), 'half_fp_features': _opencl_flags(numeric.get('half_fp_config'), {'denorm': 1, 'inf_nan': 2, 'round_to_nearest': 4, 'round_to_zero': 8, 'round_to_inf': 16, 'fma': 32})}
    return result

def _opencl_linux_icds() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for directory in (Path('/etc/OpenCL/vendors'), Path('/usr/share/OpenCL/vendors')):
        if directory.is_dir():
            for item in sorted(directory.glob('*.icd')):
                try:
                    library = item.read_text(encoding='utf-8', errors='replace').strip()
                except OSError:
                    library = None
                entries.append({'manifest': str(item), 'library': library or None})
    return entries

def _opencl_windows_icds() -> list[dict[str, Any]]:
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Khronos\\OpenCL\\Vendors')
        values: list[dict[str, Any]] = []
        index = 0
        while True:
            try:
                name, enabled, _ = winreg.EnumValue(key, index)
                values.append({'library': name, 'enabled': enabled == 0})
                index += 1
            except OSError:
                break
        return values
    except (ImportError, OSError):
        return []

def _opencl_clinfo() -> dict[str, Any]:
    path = shutil.which('clinfo')
    probe: dict[str, Any] = {'available': False, 'path': path, 'status': 'clinfo was not found', 'json': None, 'json_supported': False, 'list_output': [], 'list_output_truncated': False}
    if not path:
        return probe
    listing, list_status = _opencl_run(path, '-l')
    structured, structured_status = _opencl_run(path, '--json')
    parsed = None
    if structured_status == 0 and structured:
        try:
            parsed = json.loads(structured)
        except json.JSONDecodeError:
            pass
    lines = listing.splitlines() if list_status == 0 and listing else []
    probe.update({'available': bool(list_status == 0 or structured_status == 0), 'status': 'available' if list_status == 0 or structured_status == 0 else 'clinfo failed', 'list_output': lines[:40], 'list_output_truncated': len(lines) > 40, 'json': parsed, 'json_supported': parsed is not None})
    return probe

def _opencl_collect_opencl_info() -> dict[str, Any]:
    api, platforms = _opencl_opencl_api()
    icds = _opencl_windows_icds() if sys.platform == 'win32' else _opencl_linux_icds() if sys.platform.startswith('linux') else []
    clinfo = _opencl_clinfo()
    return {'schema_version': 1, 'platform': {'operating_system': platform.system(), 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'availability': {'opencl_api': api['available'], 'clinfo': clinfo['available'], 'detected': bool(api['available'] or clinfo['available'])}, 'probes': {'opencl_api': api, 'clinfo': clinfo}, 'installations': {'loader_library': api.get('library'), 'icd_manifests': icds, 'environment': {name: os.environ.get(name) for name in ('OCL_ICD_VENDORS', 'OPENCL_VENDOR_PATH') if os.environ.get(name)}}, 'platforms': platforms}

def _opencl_human(report: dict[str, Any]) -> None:
    print('OpenCL: ' + ('detected' if report['availability']['detected'] else 'not detected'))
    print('Loader API: %s | clinfo: %s | platforms: %s' % (report['availability']['opencl_api'], report['availability']['clinfo'], len(report['platforms'])))
    for index, item in enumerate(report['platforms']):
        print('Platform %d: %s (%s), OpenCL %s, %d device(s), %d extension(s)' % (index, item.get('name') or 'unknown', item.get('vendor') or 'unknown', item.get('version') or 'unknown', len(item['devices']), len(item['extensions'])))
        for device in item['devices']:
            limits = device['limits']
            print('  %s [%s]: %s CU, %s MiB global memory, %d extension(s)' % (device.get('name') or 'unknown', '/'.join(device['device_type']) or 'unknown', limits.get('max_compute_units', 'unknown'), limits['global_mem_size_bytes'] // (1024 * 1024) if limits.get('global_mem_size_bytes') else 'unknown', len(device['extensions'])))
    if not report['platforms']:
        print('No OpenCL platforms were enumerated. See --json probes for the reason.')

def _opencl_main() -> int:
    parser = argparse.ArgumentParser(description='Report OpenCL platforms, devices, ICD configuration, extensions, and limits.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _opencl_collect_opencl_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _opencl_human(report)
    return 0

# Embedded opengl_info collector implementation.
def _opengl_run(command: list[str], timeout: int=25) -> tuple[str | None, str | None]:
    if not shutil.which(command[0]):
        return (None, 'not installed or not on PATH')
    try:
        output = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=timeout)
        return (output, None)
    except subprocess.TimeoutExpired:
        return (None, 'timed out')
    except (OSError, subprocess.CalledProcessError) as error:
        return (None, str(error))

def _opengl_tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return {'found': bool(path), 'path': path}

def _opengl_clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _opengl_clean(item) for key, item in value.items() if item not in (None, '')}
    if isinstance(value, list):
        return [_opengl_clean(item) for item in value]
    return value

def _opengl_loader_paths() -> list[str]:
    system = platform.system()
    if system == 'Windows':
        root = Path(str(__import__('os').environ.get('SystemRoot', 'C:\\\\Windows'))) / 'System32' / 'opengl32.dll'
        return [str(root)] if root.is_file() else []
    if system == 'Darwin':
        framework = Path('/System/Library/Frameworks/OpenGL.framework/OpenGL')
        return [str(framework)] if framework.exists() else []
    candidates = [Path('/usr/lib/libGL.so.1'), Path('/usr/lib64/libGL.so.1')]
    return [str(path) for path in candidates if path.exists()]

def _opengl_parse_glxinfo(text: str) -> dict[str, Any]:
    runtime: dict[str, Any] = {}
    capability_values: dict[str, str] = {}
    extensions: set[str] = set()
    configurations: list[dict[str, str]] = []
    current_section = ''
    wrapped_extension_lines = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        match = re.match('^(server|client|OpenGL core profile|OpenGL compatibility profile|OpenGL ES profile) (?:glx )?(vendor string|version string|extensions):\\s*(.*)$', stripped, re.I)
        if match:
            group, label, value = match.groups()
            key = '%s_%s' % (re.sub('\\W+', '_', group.lower()).strip('_'), re.sub('\\W+', '_', label.lower()).strip('_'))
            if label.lower() == 'extensions':
                extensions.update(re.findall('\\b(?:GLX|GL|EGL)_[A-Za-z0-9_]+', value))
                wrapped_extension_lines = True
            else:
                runtime[key] = value or None
                wrapped_extension_lines = False
            continue
        match = re.match('^(OpenGL vendor string|OpenGL renderer string|OpenGL version string|OpenGL shading language version string):\\s*(.*)$', stripped)
        if match:
            runtime[match.group(1).lower().replace(' ', '_')] = match.group(2) or None
            wrapped_extension_lines = False
            continue
        if stripped.lower().endswith('extensions:'):
            current_section = stripped[:-1]
            wrapped_extension_lines = True
            continue
        if 'fbconfig' in stripped.lower():
            current_section = stripped
        if wrapped_extension_lines and re.match('^(?:GLX|GL|EGL)_[A-Za-z0-9_]', stripped):
            extensions.update(re.findall('\\b(?:GLX|GL|EGL)_[A-Za-z0-9_]+', stripped))
            continue
        wrapped_extension_lines = False
        match = re.match('^\\s*(GL_[A-Z0-9_]+)\\s*=\\s*(.+)$', line)
        if match:
            capability_values[match.group(1)] = match.group(2).strip()
            continue
        if current_section.lower().startswith('fbconfig') and stripped and re.match('^0x[0-9a-f]+', stripped, re.I):
            configurations.append({'source': 'glxinfo FBConfig', 'raw': stripped})
    return {'runtime': _opengl_clean(runtime), 'extensions': sorted(extensions), 'capabilities': capability_values, 'configurations': configurations}

def _opengl_collect_opengl_info() -> dict[str, Any]:
    system = platform.system()
    tools = {'glxinfo': _opengl_tool('glxinfo'), 'eglinfo': _opengl_tool('eglinfo')}
    probes: list[dict[str, Any]] = []
    details: dict[str, Any] = {'runtime': {}, 'extensions': [], 'capabilities': {}, 'configurations': []}
    limitations: list[str] = []
    available: bool | None = None
    if tools['glxinfo']['found']:
        output, error = _opengl_run(['glxinfo', '-l'])
        probes.append({'command': ['glxinfo', '-l'], 'status': 'ok' if output is not None else 'unavailable', 'error': error})
        if output:
            details = _opengl_parse_glxinfo(output)
            available = bool(details['runtime'].get('opengl_renderer_string'))
            if not available:
                limitations.append('glxinfo ran but did not expose an OpenGL renderer; the display server or context may be unavailable.')
        else:
            limitations.append('glxinfo could not create or query a GLX context; inspect the probe error and display-session configuration.')
    else:
        limitations.append('glxinfo is absent, so this script cannot safely enumerate a live OpenGL context.')
    if tools['eglinfo']['found']:
        output, error = _opengl_run(['eglinfo'])
        probes.append({'command': ['eglinfo'], 'status': 'ok' if output is not None else 'unavailable', 'error': error})
        if output:
            details['egl_summary'] = output[:200000]
    loaders = _opengl_loader_paths()
    if loaders:
        details['loader_paths'] = loaders
    if system in {'Windows', 'Darwin'}:
        limitations.append('This platform has no bundled context enumerator in the standard library. A loader/framework can exist without a usable hardware context.')
    info = _opengl_clean({'available': available, 'tools': tools, **details, 'probes': probes, 'limitations': limitations})
    info['available'] = available
    return {'platform': {'operating_system': system, 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'opengl': info}

def _opengl_print_human(report: dict[str, Any]) -> None:
    info = report['opengl']
    runtime = info['runtime']
    print('OpenGL available: %s' % ('yes' if info.get('available') else 'no' if info.get('available') is False else 'unknown'))
    print('Renderer: %s' % runtime.get('opengl_renderer_string', 'not discovered'))
    print('Version: %s' % runtime.get('opengl_version_string', 'not discovered'))
    print('Extensions: %d; capabilities: %d; framebuffer configurations: %d' % (len(info['extensions']), len(info['capabilities']), len(info['configurations'])))
    for limitation in info['limitations']:
        print('Note: ' + limitation)

def _opengl_main() -> int:
    parser = argparse.ArgumentParser(description='Report a read-only OpenGL runtime, extensions, capabilities, and configurations.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _opengl_collect_opengl_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _opengl_print_human(report)
    return 0

# Embedded vulkan_info collector implementation.
def _vulkan_run(command: list[str], timeout: int=60) -> tuple[str | None, str | None]:
    if not shutil.which(command[0]):
        return (None, 'not installed or not on PATH')
    try:
        return (subprocess.check_output(command, text=True, stderr=subprocess.STDOUT, timeout=timeout), None)
    except subprocess.TimeoutExpired:
        return (None, 'timed out')
    except (OSError, subprocess.CalledProcessError) as error:
        return (None, str(error))

def _vulkan_tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return {'found': bool(path), 'path': path}

def _vulkan_clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _vulkan_clean(item) for key, item in value.items() if item not in (None, '')}
    if isinstance(value, list):
        return [_vulkan_clean(item) for item in value]
    return value

def _vulkan_loader_paths() -> list[str]:
    system = platform.system()
    if system == 'Windows':
        import os
        path = Path(os.environ.get('SystemRoot', 'C:\\\\Windows')) / 'System32' / 'vulkan-1.dll'
        return [str(path)] if path.is_file() else []
    if system == 'Darwin':
        return []
    candidates = [Path('/usr/lib/libvulkan.so.1'), Path('/usr/lib64/libvulkan.so.1'), Path('/lib/x86_64-linux-gnu/libvulkan.so.1')]
    return [str(path) for path in candidates if path.exists()]

def _vulkan_find_values(value: Any, names: set[str], results: list[dict[str, Any]], path: str='') -> None:
    """Extract useful cross-SDK fields while retaining the complete document."""
    if isinstance(value, dict):
        for key, item in value.items():
            child = (path + '.' if path else '') + key
            if key.lower() in names:
                results.append({'path': child, 'value': item})
            _vulkan_find_values(item, names, results, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _vulkan_find_values(item, names, results, '%s[%d]' % (path, index))

def _vulkan_summary(document: Any) -> dict[str, Any]:
    found: list[dict[str, Any]] = []
    _vulkan_find_values(document, {'devicename', 'apiversion', 'driverversion', 'drivername', 'driverversion', 'vendorid', 'deviceid', 'devicetype', 'layername', 'extensionname', 'queuename', 'queuetype'}, found)
    compact: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in found:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            compact.append(item)
    return {'selected_fields': compact}

def _vulkan_parse_text_summary(text: str) -> dict[str, Any]:
    """Preserve and lightly structure vulkaninfo's cross-version summary."""
    devices: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in text.splitlines():
        gpu = re.match('^GPU(\\d+):\\s*$', line)
        if gpu:
            current = {'index': gpu.group(1)}
            devices.append(current)
            continue
        pair = re.match('^\\s*([A-Za-z][A-Za-z0-9]+)\\s*=\\s*(.*)$', line)
        if current is not None and pair:
            current[pair.group(1)] = pair.group(2).strip()
    extensions = sorted(set(re.findall('\\bVK_[A-Za-z0-9_]+\\b', text)))
    instance = re.search('Vulkan Instance Version:\\s*([^\\s]+)', text)
    return {'instance_version': instance.group(1) if instance else None, 'instance_extensions_and_layer_names': extensions, 'devices': devices, 'raw': text[:500000]}

def _vulkan_parse_json(text: str) -> tuple[Any | None, str | None]:
    try:
        return (json.loads(text), None)
    except json.JSONDecodeError as error:
        return (None, 'vulkaninfo returned non-JSON output: %s' % error.msg)

def _vulkan_vulkaninfo_json() -> tuple[Any | None, str | None]:
    """Read a Vulkan Profiles JSON report without letting the tool write here.

    Some Vulkan SDK versions print JSON to stdout, while current Windows
    builds create ``VP_VULKANINFO_*.json`` in their working directory.  A
    private temporary directory supports both forms and is deleted on return.
    """
    executable = shutil.which('vulkaninfo')
    if not executable:
        return (None, 'not installed or not on PATH')
    try:
        with tempfile.TemporaryDirectory(prefix='vulkan-info-') as directory:
            result = subprocess.run([executable, '--json'], cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            reports = list(Path(directory).glob('VP_VULKANINFO_*.json'))
            if reports:
                try:
                    return (json.loads(reports[0].read_text(encoding='utf-8')), None)
                except (OSError, json.JSONDecodeError) as error:
                    return (None, 'generated Vulkan Profiles JSON could not be read: %s' % error)
            if result.stdout.strip():
                document, error = _vulkan_parse_json(result.stdout)
                if document is not None:
                    return (document, None)
                return (None, error)
            diagnostic = result.stderr.strip() or 'vulkaninfo did not emit a JSON report'
            return (None, diagnostic)
    except subprocess.TimeoutExpired:
        return (None, 'timed out')
    except OSError as error:
        return (None, str(error))

def _vulkan_collect_vulkan_info() -> dict[str, Any]:
    tools = {'vulkaninfo': _vulkan_tool('vulkaninfo')}
    probes: list[dict[str, Any]] = []
    limitations: list[str] = []
    details: Any = {}
    summary: dict[str, Any] = {'selected_fields': []}
    available: bool | None = None
    if tools['vulkaninfo']['found']:
        text_summary, summary_error = _vulkan_run(['vulkaninfo', '--summary'])
        probes.append({'command': ['vulkaninfo', '--summary'], 'status': 'ok' if text_summary else 'unavailable', 'error': summary_error})
        if text_summary:
            summary['runtime'] = _vulkan_parse_text_summary(text_summary)
        details, error = _vulkan_vulkaninfo_json()
        probes.append({'command': ['vulkaninfo', '--json'], 'status': 'ok' if details is not None else 'unavailable', 'error': error})
        if details is not None:
            json_summary = _vulkan_summary(details)
            summary['selected_fields'] = json_summary['selected_fields']
            available = True
        else:
            available = None
            limitations.append('vulkaninfo could not enumerate a Vulkan instance or physical device; inspect the probe error.')
    else:
        limitations.append('vulkaninfo is absent, so loader presence cannot prove that a Vulkan instance/device is usable.')
    loaders = _vulkan_loader_paths()
    if loaders:
        limitations.append('A Vulkan loader was found, but it is not proof of an installed ICD or usable physical device.')
    if platform.system() == 'Darwin':
        limitations.append('macOS does not expose native Vulkan; a portability implementation such as MoltenVK must be installed for Vulkan tooling to report devices.')
    info = _vulkan_clean({'available': available, 'tools': tools, 'loader_paths': loaders, 'summary': summary, 'details': details, 'probes': probes, 'limitations': limitations})
    info['available'] = available
    return {'platform': {'operating_system': platform.system(), 'operating_system_release': platform.release(), 'machine': platform.machine()}, 'vulkan': info}

def _vulkan_print_human(report: dict[str, Any]) -> None:
    info = report['vulkan']
    summary = info['summary']['selected_fields']
    runtime = info['summary'].get('runtime', {})
    devices = [item['value'] for item in summary if item['path'].lower().endswith('devicename')]
    devices = devices or [item.get('deviceName', 'unknown') for item in runtime.get('devices', [])]
    extensions = [item['value'] for item in summary if item['path'].lower().endswith('extensionname')]
    extensions = extensions or runtime.get('instance_extensions_and_layer_names', [])
    print('Vulkan available: %s' % ('yes' if info.get('available') else 'no' if info.get('available') is False else 'unknown'))
    print('Devices (%d): %s' % (len(devices), '; '.join((str(value) for value in devices[:4])) or 'not discovered'))
    print('Reported extensions: %d; selected fields: %d' % (len(extensions), len(summary)))
    for limitation in info['limitations']:
        print('Note: ' + limitation)

def _vulkan_main() -> int:
    parser = argparse.ArgumentParser(description='Report a read-only Vulkan loader, device, layer, extension, and capability inventory.')
    parser.add_argument('--json', action='store_true', help='emit one stable JSON object for programs and LLM tool calls')
    args = parser.parse_args()
    report = _vulkan_collect_vulkan_info()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _vulkan_print_human(report)
    return 0

SECTION_NAMES = (
    "inventory", "nvidia", "amd", "cuda", "direct3d", "vulkan", "opengl", "opencl", "metal",
)
VENDOR_SECTIONS = frozenset(("nvidia", "amd"))
API_SECTIONS = frozenset(("cuda", "direct3d", "vulkan", "opengl", "opencl", "metal"))


def _run(command: list[str], timeout: int = 20) -> tuple[str | None, str | None]:
    """Run an optional local inventory command without exposing stderr."""
    if not command or not shutil.which(command[0]):
        return None, "not_found"
    try:
        completed = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, "failed_or_timed_out"
    if completed.returncode != 0:
        return None, "exited_with_%d" % completed.returncode
    return completed.stdout, None


def _add_vendor(result: set[str], text: str | None) -> None:
    if not text:
        return
    value = text.lower()
    if "nvidia" in value or "10de" in value:
        result.add("nvidia")
    if "advanced micro devices" in value or " amd" in value or "0x1002" in value or "1002:" in value:
        result.add("amd")


def _linux_inventory() -> tuple[list[dict[str, Any]], list[str], list[str]]:
    adapters: list[dict[str, Any]] = []
    evidence: list[str] = []
    vendors: set[str] = set()
    drm = Path("/sys/class/drm")
    if drm.is_dir():
        for card in sorted(drm.glob("card[0-9]*")):
            device = card / "device"
            try:
                vendor = (device / "vendor").read_text(encoding="ascii").strip()
                device_id = (device / "device").read_text(encoding="ascii").strip()
            except OSError:
                continue
            driver_link = device / "driver"
            try:
                driver = driver_link.resolve().name if driver_link.exists() else None
            except OSError:
                driver = None
            adapters.append({"name": card.name, "pci_vendor_id": vendor, "pci_device_id": device_id, "driver": driver})
            _add_vendor(vendors, vendor)
        if adapters:
            evidence.append("linux_sysfs_drm")
    lspci, error = _run(["lspci", "-nn"])
    if lspci:
        evidence.append("lspci")
        for line in lspci.splitlines():
            if "vga compatible controller" in line.lower() or "3d controller" in line.lower() or "display controller" in line.lower():
                _add_vendor(vendors, line)
    elif error and not adapters:
        evidence.append("lspci_%s" % error)
    return adapters, sorted(vendors), evidence


def _windows_inventory() -> tuple[list[dict[str, Any]], list[str], list[str]]:
    command = shutil.which("powershell") or shutil.which("pwsh")
    if not command:
        return [], [], ["powershell_not_found"]
    script = (
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name,AdapterCompatibility,PNPDeviceID,DriverVersion | "
        "ConvertTo-Json -Compress"
    )
    output, error = _run([command, "-NoProfile", "-NonInteractive", "-Command", script])
    if not output:
        return [], [], ["powershell_cim_%s" % (error or "unavailable")]
    try:
        raw = json.loads(output)
    except json.JSONDecodeError:
        return [], [], ["powershell_cim_invalid_json"]
    rows = raw if isinstance(raw, list) else [raw]
    adapters = []
    vendors: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        adapters.append({
            "name": row.get("Name"), "vendor": row.get("AdapterCompatibility"),
            "pnp_device_id": row.get("PNPDeviceID"), "driver_version": row.get("DriverVersion"),
        })
        _add_vendor(vendors, " ".join(str(row.get(key) or "") for key in ("Name", "AdapterCompatibility", "PNPDeviceID")))
    return adapters, sorted(vendors), ["powershell_cim"]


def _macos_inventory() -> tuple[list[dict[str, Any]], list[str], list[str]]:
    output, error = _run(["system_profiler", "SPDisplaysDataType", "-json"])
    if not output:
        return [], [], ["system_profiler_%s" % (error or "unavailable")]
    try:
        document = json.loads(output)
    except json.JSONDecodeError:
        return [], [], ["system_profiler_invalid_json"]
    rows = document.get("SPDisplaysDataType") if isinstance(document, dict) else []
    adapters = []
    vendors: set[str] = set()
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            adapters.append({"name": row.get("_name"), "chipset_model": row.get("sppci_model"), "vendor": row.get("spdisplays_vendor")})
            _add_vendor(vendors, " ".join(str(row.get(key) or "") for key in ("_name", "sppci_model", "spdisplays_vendor")))
    return adapters, sorted(vendors), ["system_profiler"]


def collect_inventory() -> dict[str, Any]:
    """Return lightweight, best-effort vendor detection used to choose defaults."""
    system = platform.system()
    if sys.platform == "win32":
        adapters, vendors, sources = _windows_inventory()
    elif sys.platform == "darwin":
        adapters, vendors, sources = _macos_inventory()
    elif sys.platform.startswith("linux"):
        adapters, vendors, sources = _linux_inventory()
    else:
        adapters, vendors, sources = [], [], ["no_platform_inventory_probe"]
    return {
        "operating_system": system,
        "release": platform.release(),
        "machine": platform.machine(),
        "adapters": adapters,
        "detected_vendors": vendors,
        "sources": sources,
        "limitations": [
            "Vendor detection is inventory evidence only; an undetected vendor is not proof that its hardware is absent.",
        ],
    }


def _default_sections(inventory: dict[str, Any]) -> list[str]:
    sections = ["inventory"]
    vendors = inventory.get("detected_vendors") or []
    sections.extend(name for name in ("nvidia", "amd") if name in vendors)
    if sys.platform == "win32":
        sections.append("direct3d")
    elif sys.platform == "darwin":
        sections.append("metal")
    return sections


def _parse_sections(values: list[str] | None) -> list[str]:
    requested: list[str] = []
    for value in values or []:
        for name in value.split(","):
            name = name.strip().lower()
            if not name:
                continue
            if name not in SECTION_NAMES:
                raise ValueError("unknown section %r (choose from: %s)" % (name, ", ".join(SECTION_NAMES)))
            if name not in requested:
                requested.append(name)
    return requested


def _collector_error(name: str, error: Exception) -> dict[str, Any]:
    return {"collector_error": {"section": name, "type": type(error).__name__, "message": str(error)}}


def collect_gpu_info(
    sections: list[str] | None = None,
    full: bool = False,
    skip_dxdiag: bool = False,
    include_dxdiag: bool = False,
) -> dict[str, Any]:
    """Collect selected sections, preserving every underlying collector payload.

    Overview and full reports skip DxDiag by default: the external diagnostic
    can take long enough to make a broad inventory appear stalled.  An explicit
    Direct3D selection retains its historical default of running DxDiag.
    """
    if full and sections:
        raise ValueError("--full cannot be combined with --sections")
    if skip_dxdiag and include_dxdiag:
        raise ValueError("--include-dxdiag cannot be combined with --skip-dxdiag")
    inventory = collect_inventory()
    overview = not full and not sections
    chosen = list(SECTION_NAMES) if full else (sections or _default_sections(inventory))
    if "inventory" not in chosen:
        # Inventory is always reported because it provides vendor-selection provenance.
        chosen.insert(0, "inventory")
    if skip_dxdiag:
        effective_skip_dxdiag = True
        dxdiag_mode = "skipped"
    elif overview:
        effective_skip_dxdiag = True
        dxdiag_mode = "skipped_for_overview"
    elif full and not include_dxdiag:
        effective_skip_dxdiag = True
        dxdiag_mode = "skipped_for_full"
    else:
        effective_skip_dxdiag = False
        dxdiag_mode = "enabled"
    report: dict[str, Any] = {
        "schema_version": 1,
        "platform": {"operating_system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "request": {
            "mode": "full" if full else ("selected" if sections else "overview"),
            "sections": chosen,
            "skip_dxdiag": effective_skip_dxdiag,
            "dxdiag_mode": dxdiag_mode,
        },
        "inventory": inventory,
        "vendors": {"nvidia": None, "amd": None},
        "apis": {name: None for name in sorted(API_SECTIONS)},
        "executed_sections": ["inventory"],
    }
    collectors: dict[str, Callable[[], dict[str, Any]]] = {
        "nvidia": _nvidia_collect_nvidia_info,
        "amd": lambda: _amd_collect_amd_info(skip_dxdiag=effective_skip_dxdiag),
        "cuda": _cuda_collect_cuda_info,
        "direct3d": lambda: _direct3d_collect_direct3d_info(skip_dxdiag=effective_skip_dxdiag),
        "vulkan": _vulkan_collect_vulkan_info,
        "opengl": _opengl_collect_opengl_info,
        "opencl": _opencl_collect_opencl_info,
        "metal": _metal_collect_metal_info,
    }
    for name in chosen:
        if name == "inventory":
            continue
        try:
            payload = collectors[name]()
        except Exception as error:  # One optional runtime must not hide other requested evidence.
            payload = _collector_error(name, error)
        if name in VENDOR_SECTIONS:
            report["vendors"][name] = payload
        else:
            report["apis"][name] = payload
        report["executed_sections"].append(name)
    return report


def _print_human(report: dict[str, Any]) -> None:
    inventory = report["inventory"]
    print("GPU overview: %s" % report["request"]["mode"])
    print("Detected vendors: %s" % (", ".join(inventory.get("detected_vendors", [])) or "none"))
    adapters = inventory.get("adapters", [])
    print("Adapters (%d): %s" % (len(adapters), "; ".join(str(item.get("name") or item.get("chipset_model") or "unknown") for item in adapters) or "not reported"))
    print("Executed sections: %s" % ", ".join(report["executed_sections"]))
    for group in ("vendors", "apis"):
        for name, payload in report[group].items():
            if payload is not None:
                print("%s: collected" % name)


def main() -> int:
    parser = argparse.ArgumentParser(description="Consolidated GPU inventory and graphics, compute, and vendor capability report.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON document")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--sections", action="append", metavar="LIST", help="comma-separated sections; repeatable: %s" % ", ".join(SECTION_NAMES))
    selection.add_argument("--full", action="store_true", help="run every section, including optional runtimes")
    dxdiag = parser.add_mutually_exclusive_group()
    dxdiag.add_argument("--include-dxdiag", action="store_true", help="allow DxDiag in a full report (explicit Direct3D already enables it)")
    dxdiag.add_argument("--skip-dxdiag", action="store_true", help="when Direct3D runs, do not launch DxDiag or create its temporary report")
    args = parser.parse_args()
    try:
        sections = _parse_sections(args.sections)
    except ValueError as error:
        parser.error(str(error))
    report = collect_gpu_info(
        sections=sections or None,
        full=args.full,
        skip_dxdiag=args.skip_dxdiag,
        include_dxdiag=args.include_dxdiag,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str, allow_nan=False))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
