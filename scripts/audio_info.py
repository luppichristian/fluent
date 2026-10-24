#!/usr/bin/env python3
# description: Unified audio capability facade with the OpenAL collector nested intact.
"""Report locally observable audio-runtime capabilities.

This is the public audio entry point. Its built-in OpenAL probe nests its
complete ``openal`` value under ``audio.openal``. The tool intentionally does
not infer hardware features or combine audio APIs into a lossy common shape.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import ctypes.util
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 2

_PROBE_STATUSES = {"available", "unsupported", "unavailable", "denied", "failed", "unknown"}
_COMMON_REDACTION_LEVELS = ("none", "default", "strict")


# These output helpers intentionally live in this file.  Fluent's diagnostic
# scripts can be copied and executed individually, so the public audio command
# must not depend on a sibling module at runtime.
def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    """Add standalone LLM, privacy, compatibility, and snapshot controls."""
    parser.add_argument(
        "--profile", choices=("full", "llm", "summary"), default="full",
        help="output view: full evidence (default), bounded LLM view, or compact summary",
    )
    parser.add_argument(
        "--redact", choices=_COMMON_REDACTION_LEVELS, default="none",
        help="replace sensitive local identifiers before output or saving (default: none for compatibility)",
    )
    parser.add_argument("--requirements", metavar="PATH", help="evaluate a JSON requirements manifest against this report")
    parser.add_argument("--compare", metavar="PATH", help="compare the report with a prior JSON snapshot")
    parser.add_argument("--save", metavar="PATH", help="write the final JSON report to a snapshot file")
    parser.add_argument("--envelope", action="store_true", help="wrap full evidence in the common tool/status/metadata envelope")
    parser.add_argument("--output-schema", action="store_true", help="print the common requirements-manifest schema and exit")
    parser.add_argument("--report-schema", action="store_true", help="print the audio-report JSON Schema and exit")


def requirements_schema() -> dict[str, Any]:
    """Return the portable requirements-manifest contract without a dependency."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://fluent.local/schemas/diagnostic-requirements-1.json",
        "schema_version": 1,
        "type": "object",
        "required": ["requirements"],
        "properties": {"requirements": {"type": "array", "items": {"type": "object", "required": ["path"], "properties": {"id": {"type": "string"}, "path": {"type": "string"}, "operator": {"enum": ["exists", "equals", "not_equals", "contains", "gte", "lte"]}, "description": {"type": "string"}}}}},
        "description": "A requirements manifest is an object containing a requirements array.",
        "requirement": {
            "id": "stable human-readable identifier",
            "path": "dot path in the emitted full report; list indexes use [0]",
            "operator": ["exists", "equals", "not_equals", "contains", "gte", "lte"],
            "value": "required except for exists",
            "description": "optional explanation shown in the result",
        },
        "status_values": sorted(_PROBE_STATUSES),
        "example": {"requirements": [{"id": "openal", "path": "audio.openal.available", "operator": "equals", "value": True}]},
    }


def report_schema() -> dict[str, Any]:
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "https://fluent.local/schemas/audio-info-report-2.json", "title": "Fluent audio_info report", "oneOf": [{"type": "object", "required": ["schema_version", "platform", "audio"], "properties": {"schema_version": {"type": "integer", "const": SCHEMA_VERSION}, "platform": {"type": "object"}, "audio": {"type": "object"}}, "additionalProperties": True}, {"type": "object", "required": ["schema_version", "tool", "status", "metadata", "data"], "properties": {"schema_version": {"type": "integer", "const": 1}, "tool": {"const": "audio_info"}, "status": {"type": "string"}, "metadata": {"type": "object"}, "data": {"type": "object"}}, "additionalProperties": True}]}


def _common_redacted(value: Any) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:12]
    return "<redacted:%s>" % digest


def _common_sensitive_key(key: str, level: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    default = (
        "serial", "uuid", "mac", "ip", "address", "hostname", "fqdn", "username",
        "qualified_name", "home", "path", "pnp_device_id", "pci_bus_id", "device_id",
        "executable", "working_directory",
    )
    strict = default + ("name", "model", "manufacturer", "vendor", "driver", "group", "environment", "variables")
    return any(normalized == token or normalized.startswith(token + "_") or normalized.endswith("_" + token) for token in (strict if level == "strict" else default))


def redact(value: Any, level: str) -> Any:
    """Deep-copy and replace privacy-sensitive values without dropping evidence."""
    if level == "none":
        return copy.deepcopy(value)
    if isinstance(value, dict):
        return {
            # A sensitive-looking plural key can also be a structural section
            # (for example, ``drivers``).  Preserve containers so consumers
            # can still summarize the report; redact their sensitive leaves.
            key: _common_redacted(item) if _common_sensitive_key(str(key), level) and not isinstance(item, (dict, list)) and item not in (None, "") else redact(item, level)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, level) for item in value]
    return value


def _resolve_requirement_path(document: Any, path: str) -> tuple[bool, Any]:
    current = document
    for part in path.split("."):
        match = re.fullmatch(r"([^\[]+)?(?:\[(\d+)\])?", part)
        if not match:
            return False, None
        key, index = match.groups()
        if key:
            if not isinstance(current, dict) or key not in current:
                return False, None
            current = current[key]
        if index is not None:
            try:
                current = current[int(index)]
            except (IndexError, TypeError):
                return False, None
    return True, current


def evaluate_requirements(report: dict[str, Any], path: str) -> dict[str, Any]:
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"status": "failed", "manifest": path, "error": str(error), "results": []}
    entries = manifest.get("requirements") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return {"status": "failed", "manifest": path, "error": "manifest must contain a requirements array", "results": []}
    results: list[dict[str, Any]] = []
    allowed = {"exists", "equals", "not_equals", "contains", "gte", "lte"}
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            results.append({"id": "requirement-%d" % index, "status": "failed", "error": "requirement needs a string path"})
            continue
        exists, actual = _resolve_requirement_path(report, item["path"])
        operator = item.get("operator", "exists")
        expected = item.get("value")
        status = "unknown" if not exists or actual is None else "failed"
        try:
            if operator == "exists":
                status = "passed" if exists and actual is not None else "unknown"
            elif operator == "equals" and exists and actual is not None:
                status = "passed" if actual == expected else "failed"
            elif operator == "not_equals" and exists and actual is not None:
                status = "passed" if actual != expected else "failed"
            elif operator == "contains" and exists and actual is not None:
                status = "passed" if expected in actual else "failed"
            elif operator == "gte" and exists and actual is not None:
                status = "passed" if actual >= expected else "failed"
            elif operator == "lte" and exists and actual is not None:
                status = "passed" if actual <= expected else "failed"
            elif operator not in allowed:
                status, actual = "failed", "unsupported operator: %s" % operator
        except (TypeError, ValueError):
            status = "unknown"
        results.append({"id": item.get("id", "requirement-%d" % index), "description": item.get("description"), "path": item["path"], "operator": operator, "expected": expected, "actual": actual, "status": status})
    overall = "passed" if results and all(item["status"] == "passed" for item in results) else "failed" if any(item["status"] == "failed" for item in results) else "unknown"
    return {"status": overall, "manifest": path, "results": results}


def _flatten(value: Any, prefix: str = "", result: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {} if result is None else result
    if isinstance(value, dict):
        for key, item in value.items():
            _flatten(item, "%s.%s" % (prefix, key) if prefix else str(key), result)
    elif isinstance(value, list):
        result[prefix] = value
    else:
        result[prefix] = value
    return result


def compare_snapshot(report: dict[str, Any], path: str, maximum_changes: int = 200) -> dict[str, Any]:
    try:
        prior = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"status": "failed", "snapshot": path, "error": str(error), "changes": []}
    def comparable(value: Any) -> Any:
        value = copy.deepcopy(value)
        if isinstance(value, dict):
            value.pop("comparison", None)
            metadata = value.get("metadata")
            if isinstance(metadata, dict):
                metadata.pop("collected_at_utc", None)
            for item in value.values():
                comparable(item)
        elif isinstance(value, list):
            for item in value: comparable(item)
        return value
    before, after = _flatten(comparable(prior)), _flatten(comparable(report))
    def change_kind(key: str) -> str:
        if key not in before:
            return "added"
        if key not in after:
            return "removed"
        old, new = before[key], after[key]
        if (old is True and new is False) or (isinstance(old, (int, float)) and not isinstance(old, bool) and isinstance(new, (int, float)) and not isinstance(new, bool) and new < old):
            return "regressed"
        if isinstance(old, str) and isinstance(new, str) and old in {"available", "passed"} and new in {"unavailable", "unsupported", "denied", "failed"}:
            return "regressed"
        return "changed"
    changes = [
        {"path": key, "before": before.get(key), "after": after.get(key), "kind": change_kind(key)}
        for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)
    ]
    return {"status": "changed" if changes else "unchanged", "snapshot": path, "change_count": len(changes), "truncated": len(changes) > maximum_changes, "changes": changes[:maximum_changes]}


def finalize_report(
    report: dict[str, Any], args: argparse.Namespace, tool: str,
    summary: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Apply standalone output controls after collection and before printing."""
    enriched = copy.deepcopy(report)
    enriched.setdefault("metadata", {})
    enriched["metadata"].update({"tool": tool, "collected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "redaction": args.redact})
    if args.requirements:
        enriched["compatibility"] = evaluate_requirements(enriched, args.requirements)
    if args.compare:
        enriched["comparison"] = compare_snapshot(enriched, args.compare)
    # A result's path is diagnostic vocabulary, not the local value it points
    # to. Keep it readable while redacting the referenced values themselves.
    if args.redact != "none":
        compatibility = enriched.get("compatibility")
        if isinstance(compatibility, dict):
            for result in compatibility.get("results", []):
                if isinstance(result, dict) and _common_sensitive_key(str(result.get("path", "")), args.redact):
                    for key in ("actual", "expected"):
                        if result.get(key) not in (None, "", [], {}):
                            result[key] = _common_redacted(result[key])
        comparison = enriched.get("comparison")
        if isinstance(comparison, dict):
            for change in comparison.get("changes", []):
                if isinstance(change, dict) and _common_sensitive_key(str(change.get("path", "")), args.redact):
                    for key in ("before", "after"):
                        if change.get(key) not in (None, "", [], {}):
                            change[key] = _common_redacted(change[key])
    redacted = redact(enriched, args.redact)
    # Generic privacy handling protects ordinary filesystem paths. Restore the
    # symbolic field paths in transport results so a diff remains actionable.
    for group in ("compatibility", "comparison"):
        original = enriched.get(group)
        rendered = redacted.get(group) if isinstance(redacted, dict) else None
        if not isinstance(original, dict) or not isinstance(rendered, dict):
            continue
        original_rows = original.get("results" if group == "compatibility" else "changes", [])
        rendered_rows = rendered.get("results" if group == "compatibility" else "changes", [])
        for source, target in zip(original_rows, rendered_rows):
            if isinstance(source, dict) and isinstance(target, dict) and "path" in source:
                target["path"] = source["path"]
    if args.save:
        target = Path(args.save)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(redacted, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    if args.envelope and args.profile == "full":
        compact = summary(redacted)
        return {"schema_version": 1, "tool": tool, "metadata": redacted["metadata"], "status": compact.get("status", "unknown"), "data": redacted, "compatibility": redacted.get("compatibility"), "comparison": redacted.get("comparison")}
    if args.profile == "full":
        return redacted
    compact = summary(redacted)
    return {"schema_version": 1, "tool": tool, "metadata": redacted["metadata"], "status": compact.get("status", "unknown"), "summary": compact, "compatibility": redacted.get("compatibility"), "comparison": redacted.get("comparison")}


def _probe(
    status: str,
    source: str,
    *,
    data: Any = None,
    errors: list[dict[str, str]] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Return the common, LLM-friendly representation for a native probe."""
    if status not in _PROBE_STATUSES:
        raise ValueError("invalid probe status: %s" % status)
    return {
        "status": status,
        "provenance": {"source": source, "active_probe": False},
        "errors": errors or [],
        "data": data,
        "limitations": limitations or [],
    }


def _error(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def _run_json_command(
    command: list[str], source: str, timeout: int = 12
) -> dict[str, Any]:
    """Run an optional local inspector and retain failure class as evidence."""
    if not command or not shutil.which(command[0]):
        return _probe("unavailable", source, errors=[_error("tool_not_found", command[0] if command else "")])
    try:
        completed = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return _probe("failed", source, errors=[_error("timeout", "probe exceeded %ss" % timeout)])
    except OSError as exc:
        return _probe("failed", source, errors=[_error("launch_failed", str(exc))])
    if completed.returncode:
        return _probe(
            "failed", source,
            errors=[_error("nonzero_exit", "exit %s: %s" % (completed.returncode, completed.stderr.strip()))],
        )
    try:
        return _probe("available", source, data=json.loads(completed.stdout))
    except json.JSONDecodeError as exc:
        return _probe("failed", source, errors=[_error("invalid_json", str(exc))])


def _endpoint(
    name: str | None,
    direction: str,
    *,
    identifier: str | None = None,
    state: str | None = None,
    driver: dict[str, Any] | None = None,
    formats: dict[str, Any] | None = None,
    default_roles: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Use one conservative endpoint shape across OS backends."""
    return {
        "name": name,
        "direction": direction,
        "identifier": identifier,
        "state": state,
        "default_roles": default_roles or [],
        "formats": formats or {"sample_rates_hz": [], "sample_formats": [], "channel_layouts": []},
        "driver": driver or {},
        "metadata": metadata or {},
    }


def _redaction_token(value: Any) -> str | None:
    if value is None:
        return None
    digest = hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()
    return "redacted:%s" % digest[:12]


def _redact_audio_metadata(value: Any, policy: str, key: str = "") -> Any:
    """Redact local endpoint identifiers while retaining stable correlation tokens."""
    if policy == "none":
        return value
    sensitive = {
        "identifier", "id", "device_id", "instance_id", "serial", "uuid", "address",
        "mac", "path", "name", "description", "friendlyname", "node_name",
    }
    if isinstance(value, dict):
        return {name: _redact_audio_metadata(item, policy, name.lower()) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact_audio_metadata(item, policy, key) for item in value]
    if key in sensitive or (policy == "strict" and isinstance(value, str) and key not in {"direction", "state", "status"}):
        return _redaction_token(value)
    return value


# OpenAL C API constants.  The native probe below is intentionally self-
# contained so this public command has no package or sibling-file dependency.
_AL_VENDOR = 0xB001
_AL_VERSION = 0xB002
_AL_RENDERER = 0xB003
_AL_EXTENSIONS = 0xB004
_ALC_MAJOR_VERSION = 0x1000
_ALC_MINOR_VERSION = 0x1001
_ALC_ATTRIBUTES_SIZE = 0x1002
_ALC_ALL_ATTRIBUTES = 0x1003
_ALC_DEFAULT_DEVICE_SPECIFIER = 0x1004
_ALC_DEVICE_SPECIFIER = 0x1005
_ALC_EXTENSIONS = 0x1006
_ALC_FREQUENCY = 0x1007
_ALC_REFRESH = 0x1008
_ALC_MONO_SOURCES = 0x1010
_ALC_STEREO_SOURCES = 0x1011
_ALC_DEFAULT_ALL_DEVICES_SPECIFIER = 0x1012
_ALC_ALL_DEVICES_SPECIFIER = 0x1013
_ALC_ENUMERATION_EXT = "ALC_ENUMERATION_EXT"
_ALC_ENUMERATE_ALL_EXT = "ALC_ENUMERATE_ALL_EXT"
_ALC_HRTF_SOFT = "ALC_SOFT_HRTF"
_ALC_NUM_HRTF_SPECIFIERS_SOFT = 0x1994
_ALC_HRTF_SPECIFIER_SOFT = 0x1995


def _openal_compact(value: Any) -> Any:
    """Keep null evidence while omitting empty-string native artifacts."""
    if isinstance(value, dict):
        return {
            key: _openal_compact(item)
            for key, item in value.items()
            if item != ""
        }
    if isinstance(value, list):
        return [_openal_compact(item) for item in value]
    return value


def _openal_find_candidates() -> list[str]:
    names = ["OpenAL32", "openal"]
    candidates: list[str] = []
    for name in names:
        found = ctypes.util.find_library(name)
        if found and found not in candidates:
            candidates.append(found)
    if sys.platform == "win32":
        root = os.environ.get("SystemRoot")
        if root:
            path = str(Path(root) / "System32" / "OpenAL32.dll")
            if Path(path).exists() and path not in candidates:
                candidates.append(path)
        if "OpenAL32.dll" not in candidates:
            candidates.append("OpenAL32.dll")
    elif sys.platform == "darwin":
        framework = "/System/Library/Frameworks/OpenAL.framework/OpenAL"
        if Path(framework).exists() and framework not in candidates:
            candidates.append(framework)
    else:
        for name in ("libopenal.so.1", "libopenal.so"):
            if name not in candidates:
                candidates.append(name)
    return candidates


def _openal_load_library(
    candidates: list[str],
) -> tuple[Any | None, str | None, list[dict[str, str]]]:
    attempts: list[dict[str, str]] = []
    for candidate in candidates:
        try:
            # OpenAL's exported C API uses cdecl, including on 32-bit Windows.
            library = ctypes.CDLL(candidate)
            attempts.append({"candidate": candidate, "result": "loaded"})
            return library, candidate, attempts
        except OSError as error:
            attempts.append(
                {"candidate": candidate, "result": "load_failed", "error": str(error)}
            )
    return None, None, attempts


def _openal_decode(pointer: int | None) -> str | None:
    if not pointer:
        return None
    try:
        return ctypes.string_at(pointer).decode("utf-8", errors="replace")
    except (ValueError, OSError):
        return None


def _openal_string_list(pointer: int | None, maximum: int = 65536) -> list[str]:
    """Decode a NUL-separated device list without reading past its bound."""
    if not pointer:
        return []
    values: list[str] = []
    address = int(pointer)
    current = bytearray()
    try:
        for index in range(maximum):
            byte = ctypes.c_ubyte.from_address(address + index).value
            if byte:
                current.append(byte)
                continue
            if not current:
                break
            values.append(current.decode("utf-8", errors="replace"))
            current.clear()
    except (ValueError, OSError):
        return values
    return values


def _openal_space_words(value: str | None) -> list[str]:
    return value.split() if value else []


def _openal_configure(library: Any) -> None:
    library.alcOpenDevice.argtypes = [ctypes.c_char_p]
    library.alcOpenDevice.restype = ctypes.c_void_p
    library.alcCloseDevice.argtypes = [ctypes.c_void_p]
    library.alcCloseDevice.restype = ctypes.c_int
    library.alcCreateContext.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    library.alcCreateContext.restype = ctypes.c_void_p
    library.alcDestroyContext.argtypes = [ctypes.c_void_p]
    library.alcMakeContextCurrent.argtypes = [ctypes.c_void_p]
    library.alcMakeContextCurrent.restype = ctypes.c_int
    library.alcGetString.argtypes = [ctypes.c_void_p, ctypes.c_int]
    library.alcGetString.restype = ctypes.c_void_p
    library.alcGetIntegerv.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
    ]
    library.alcGetError.argtypes = [ctypes.c_void_p]
    library.alcGetError.restype = ctypes.c_int
    library.alcIsExtensionPresent.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    library.alcIsExtensionPresent.restype = ctypes.c_int
    library.alGetString.argtypes = [ctypes.c_int]
    library.alGetString.restype = ctypes.c_void_p
    library.alGetError.restype = ctypes.c_int


def _openal_alc_integer(library: Any, device: Any, token: int) -> int | None:
    value = ctypes.c_int()
    try:
        library.alcGetIntegerv(device, token, 1, ctypes.byref(value))
        return int(value.value)
    except (AttributeError, OSError):
        return None


def _openal_alc_attributes(library: Any, device: Any) -> list[int]:
    count = _openal_alc_integer(library, device, _ALC_ATTRIBUTES_SIZE)
    if count is None or count < 1 or count > 256:
        return []
    values = (ctypes.c_int * count)()
    try:
        library.alcGetIntegerv(device, _ALC_ALL_ATTRIBUTES, count, values)
        return [int(value) for value in values]
    except (AttributeError, OSError, ValueError):
        return []


def _openal_global_probe(library: Any) -> dict[str, Any]:
    extensions = _openal_decode(library.alcGetString(None, _ALC_EXTENSIONS))
    has_enumeration = bool(
        library.alcIsExtensionPresent(None, _ALC_ENUMERATION_EXT.encode())
    )
    has_all = bool(library.alcIsExtensionPresent(None, _ALC_ENUMERATE_ALL_EXT.encode()))
    return {
        "default_device": _openal_decode(
            library.alcGetString(None, _ALC_DEFAULT_DEVICE_SPECIFIER)
        ),
        "default_all_device": (
            _openal_decode(library.alcGetString(None, _ALC_DEFAULT_ALL_DEVICES_SPECIFIER))
            if has_all
            else None
        ),
        "extensions": _openal_space_words(extensions),
        "devices": (
            _openal_string_list(library.alcGetString(None, _ALC_DEVICE_SPECIFIER))
            if has_enumeration
            else []
        ),
        "all_devices": (
            _openal_string_list(library.alcGetString(None, _ALC_ALL_DEVICES_SPECIFIER))
            if has_all
            else []
        ),
        "device_enumeration": {
            "ALC_ENUMERATION_EXT": has_enumeration,
            "ALC_ENUMERATE_ALL_EXT": has_all,
        },
    }


def _openal_context_probe(library: Any) -> tuple[dict[str, Any], str | None]:
    device = library.alcOpenDevice(None)
    if not device:
        return {}, "alcOpenDevice(NULL) returned no device"
    context = None
    try:
        context = library.alcCreateContext(device, None)
        if not context:
            return {
                "device": {
                    "name": _openal_decode(
                        library.alcGetString(device, _ALC_DEVICE_SPECIFIER)
                    )
                }
            }, "alcCreateContext returned no context"
        if not library.alcMakeContextCurrent(context):
            return {
                "device": {
                    "name": _openal_decode(
                        library.alcGetString(device, _ALC_DEVICE_SPECIFIER)
                    )
                }
            }, "alcMakeContextCurrent failed"
        alc_extensions = _openal_space_words(
            _openal_decode(library.alcGetString(device, _ALC_EXTENSIONS))
        )
        device_data: dict[str, Any] = {
            "name": _openal_decode(library.alcGetString(device, _ALC_DEVICE_SPECIFIER)),
            "major_version": _openal_alc_integer(library, device, _ALC_MAJOR_VERSION),
            "minor_version": _openal_alc_integer(library, device, _ALC_MINOR_VERSION),
            "configuration": {
                "frequency_hz": _openal_alc_integer(library, device, _ALC_FREQUENCY),
                "refresh_hz": _openal_alc_integer(library, device, _ALC_REFRESH),
                "mono_sources": _openal_alc_integer(library, device, _ALC_MONO_SOURCES),
                "stereo_sources": _openal_alc_integer(library, device, _ALC_STEREO_SOURCES),
                "attribute_count": _openal_alc_integer(
                    library, device, _ALC_ATTRIBUTES_SIZE
                ),
                "raw_attribute_vector": _openal_alc_attributes(library, device),
            },
            "extensions": alc_extensions,
            "error_code_after_queries": library.alcGetError(device),
        }
        al_data = {
            "vendor": _openal_decode(library.alGetString(_AL_VENDOR)),
            "renderer": _openal_decode(library.alGetString(_AL_RENDERER)),
            "version": _openal_decode(library.alGetString(_AL_VERSION)),
            "extensions": _openal_space_words(
                _openal_decode(library.alGetString(_AL_EXTENSIONS))
            ),
            "error_code_after_queries": library.alGetError(),
        }
        hrtf: dict[str, Any] = {"supported": _ALC_HRTF_SOFT in alc_extensions}
        if hrtf["supported"]:
            hrtf["available_specifier_count"] = _openal_alc_integer(
                library, device, _ALC_NUM_HRTF_SPECIFIERS_SOFT
            )
            function = getattr(library, "alcGetStringiSOFT", None)
            names: list[str] = []
            if function is not None:
                function.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
                function.restype = ctypes.c_void_p
                for index in range(
                    max(0, hrtf.get("available_specifier_count") or 0)
                ):
                    name = _openal_decode(
                        function(device, _ALC_HRTF_SPECIFIER_SOFT, index)
                    )
                    if name is not None:
                        names.append(name)
            hrtf["specifiers"] = names
            hrtf["specifier_query_function_exposed"] = function is not None
        return _openal_compact(
            {"device": device_data, "al": al_data, "capabilities": {"hrtf": hrtf}}
        ), None
    except (AttributeError, OSError, TypeError, ValueError) as error:
        return {}, "OpenAL runtime query failed: %s" % error
    finally:
        if context:
            try:
                library.alcMakeContextCurrent(None)
                library.alcDestroyContext(context)
            except (AttributeError, OSError):
                pass
        try:
            library.alcCloseDevice(device)
        except (AttributeError, OSError):
            pass


def _openal_info_command() -> dict[str, Any]:
    executable = shutil.which("openal-info")
    if not executable:
        return {"available": False, "source": "openal-info_not_found", "lines": []}
    try:
        completed = subprocess.run(
            [executable],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
        )
        return {
            "available": True,
            "source": "openal-info",
            "exit_code": completed.returncode,
            "lines": completed.stdout.splitlines(),
        }
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "available": True,
            "source": "openal-info_failed_or_timed_out",
            "error": str(error),
            "lines": [],
        }


def _collect_openal_info(
    probe_context: bool = True, include_openal_info: bool = False
) -> dict[str, Any]:
    """Collect OpenAL evidence without raising when its runtime is absent."""
    candidates = _openal_find_candidates()
    report: dict[str, Any] = {
        "platform": {
            "operating_system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "openal": {
            "available": False,
            "library": {
                "candidates": candidates,
                "loaded_path": None,
                "load_attempts": [],
            },
            "global": {
                "default_device": None,
                "default_all_device": None,
                "extensions": [],
                "devices": [],
                "all_devices": [],
                "device_enumeration": {},
            },
            "context": {
                "attempted": False,
                "created": False,
                "details": {},
                "failure": None,
            },
            "native_tool": None,
            "limitations": [],
        },
    }
    openal = report["openal"]
    library, loaded_path, attempts = _openal_load_library(candidates)
    openal["library"]["loaded_path"] = loaded_path
    openal["library"]["load_attempts"] = attempts
    if library is None:
        openal["limitations"].append("No loadable OpenAL shared library was found.")
        if include_openal_info:
            openal["native_tool"] = _openal_info_command()
        return _openal_compact(report)
    openal["available"] = True
    try:
        _openal_configure(library)
        openal["global"] = _openal_global_probe(library)
    except (AttributeError, OSError) as error:
        openal["limitations"].append(
            "The loaded library did not expose the expected OpenAL C API: %s" % error
        )
        return _openal_compact(report)
    if probe_context:
        openal["context"]["attempted"] = True
        details, failure = _openal_context_probe(library)
        openal["context"]["details"] = details
        openal["context"]["failure"] = failure
        openal["context"]["created"] = failure is None
        if failure:
            openal["limitations"].append(
                "A temporary default-device context could not be created: " + failure
            )
    else:
        openal["limitations"].append(
            "No context was created; renderer, AL extensions, and context "
            "configuration are unreported."
        )
    if include_openal_info:
        openal["native_tool"] = _openal_info_command()
    return _openal_compact(report)


def _windows_default_endpoint_roles() -> dict[str, Any]:
    """Ask IMMDeviceEnumerator for Windows' three default endpoint roles.

    The small in-process C# definition uses only the documented COM interfaces.
    It creates no IAudioClient and never opens a playback or capture stream.
    """
    source = r'''
using System;
using System.Runtime.InteropServices;
public static class FluentAudioDefaultEndpoints {
 [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 private interface IMMDeviceEnumerator {
  int EnumAudioEndpoints(int dataFlow, int stateMask, out IntPtr devices);
  int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice endpoint);
  int GetDevice(string id, out IMMDevice device);
  int RegisterEndpointNotificationCallback(IntPtr callback);
  int UnregisterEndpointNotificationCallback(IntPtr callback);
 }
 [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 private interface IMMDevice {
  int Activate(ref Guid iid, int clsCtx, IntPtr parameters, out IntPtr value);
  int OpenPropertyStore(int access, out IntPtr properties);
  int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id);
  int GetState(out int state);
 }
 public static string GetDefaultId(int flow, int role) {
  IMMDeviceEnumerator enumerator = null; IMMDevice device = null;
  try {
   enumerator = (IMMDeviceEnumerator)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")));
   int hr = enumerator.GetDefaultAudioEndpoint(flow, role, out device);
   if (hr < 0 || device == null) return null;
   string id; hr = device.GetId(out id); return hr < 0 ? null : id;
  } catch { return null; }
  finally { if (device != null) Marshal.ReleaseComObject(device); if (enumerator != null) Marshal.ReleaseComObject(enumerator); }
 }
}
'''
    script = "$source = @'\n%s\n'@\nAdd-Type -TypeDefinition $source\n[ordered]@{ render_console = [FluentAudioDefaultEndpoints]::GetDefaultId(0,0); render_multimedia = [FluentAudioDefaultEndpoints]::GetDefaultId(0,1); render_communications = [FluentAudioDefaultEndpoints]::GetDefaultId(0,2); capture_console = [FluentAudioDefaultEndpoints]::GetDefaultId(1,0); capture_multimedia = [FluentAudioDefaultEndpoints]::GetDefaultId(1,1); capture_communications = [FluentAudioDefaultEndpoints]::GetDefaultId(1,2) } | ConvertTo-Json -Compress" % source
    probe = _run_json_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], "windows.immdevice.default_endpoints", timeout=20)
    if probe["status"] == "available":
        probe["provenance"]["active_probe"] = True
    return probe


def _windows_default_endpoint_formats() -> dict[str, Any]:
    """Read the shared-mode mix format of default endpoints when opted in.

    IAudioClient activation is deliberately separate from passive endpoint
    inventory. GetMixFormat performs no stream initialization, playback, or
    recording, but can still touch a device driver.
    """
    source = r'''
using System;
using System.Runtime.InteropServices;
public static class FluentAudioEndpointFormats {
 [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 private interface IMMDeviceEnumerator { int EnumAudioEndpoints(int flow, int state, out IntPtr collection); int GetDefaultAudioEndpoint(int flow, int role, out IMMDevice endpoint); int GetDevice(string id, out IMMDevice endpoint); int RegisterEndpointNotificationCallback(IntPtr callback); int UnregisterEndpointNotificationCallback(IntPtr callback); }
 [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 private interface IMMDevice { int Activate(ref Guid iid, int clsCtx, IntPtr parameters, [MarshalAs(UnmanagedType.Interface)] out IAudioClient value); int OpenPropertyStore(int access, out IntPtr properties); int GetId([MarshalAs(UnmanagedType.LPWStr)] out string id); int GetState(out int state); }
 [ComImport, Guid("1CB9AD4C-DBFA-4c32-B178-C2F568A703B2"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
 private interface IAudioClient { int Initialize(int shareMode, int streamFlags, long bufferDuration, long periodicity, IntPtr format, IntPtr sessionGuid); int GetBufferSize(out uint frames); int GetStreamLatency(out long latency); int GetCurrentPadding(out uint frames); int IsFormatSupported(int shareMode, IntPtr format, out IntPtr closest); int GetMixFormat(out IntPtr format); }
 [StructLayout(LayoutKind.Sequential, Pack=2)]
 private struct WAVEFORMATEX { public ushort tag; public ushort channels; public uint samplesPerSec; public uint avgBytesPerSec; public ushort blockAlign; public ushort bitsPerSample; public ushort cbSize; }
 private static object Get(int flow, int role) { IMMDeviceEnumerator e=null; IMMDevice d=null; IAudioClient c=null; IntPtr p=IntPtr.Zero; try { e=(IMMDeviceEnumerator)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("BCDE0395-E52F-467C-8E3D-C4579291692E"))); if(e.GetDefaultAudioEndpoint(flow,role,out d)<0 || d==null)return null; Guid iid=new Guid("1CB9AD4C-DBFA-4c32-B178-C2F568A703B2"); if(d.Activate(ref iid,23,IntPtr.Zero,out c)<0 || c==null)return null; if(c.GetMixFormat(out p)<0 || p==IntPtr.Zero)return null; var w=(WAVEFORMATEX)Marshal.PtrToStructure(p,typeof(WAVEFORMATEX)); return new { format_tag=w.tag, channels=w.channels, sample_rate_hz=w.samplesPerSec, average_bytes_per_second=w.avgBytesPerSec, block_align=w.blockAlign, bits_per_sample=w.bitsPerSample, extra_size=w.cbSize }; } catch { return null; } finally { if(p!=IntPtr.Zero)Marshal.FreeCoTaskMem(p); if(c!=null)Marshal.ReleaseComObject(c); if(d!=null)Marshal.ReleaseComObject(d); if(e!=null)Marshal.ReleaseComObject(e); } }
 public static object RenderConsole(){return Get(0,0);} public static object RenderMultimedia(){return Get(0,1);} public static object RenderCommunications(){return Get(0,2);} public static object CaptureConsole(){return Get(1,0);} public static object CaptureMultimedia(){return Get(1,1);} public static object CaptureCommunications(){return Get(1,2);}
}
'''
    script = "$source = @'\n%s\n'@\nAdd-Type -TypeDefinition $source\n[ordered]@{ render_console = [FluentAudioEndpointFormats]::RenderConsole(); render_multimedia = [FluentAudioEndpointFormats]::RenderMultimedia(); render_communications = [FluentAudioEndpointFormats]::RenderCommunications(); capture_console = [FluentAudioEndpointFormats]::CaptureConsole(); capture_multimedia = [FluentAudioEndpointFormats]::CaptureMultimedia(); capture_communications = [FluentAudioEndpointFormats]::CaptureCommunications() } | ConvertTo-Json -Depth 4 -Compress" % source
    probe = _run_json_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], "windows.wasapi.IAudioClient.GetMixFormat", timeout=20)
    if probe["status"] == "available":
        probe["provenance"]["active_probe"] = True
    return probe


def _windows_audio_backend(include_endpoint_formats: bool = False) -> dict[str, Any]:
    """Inventory Windows endpoint PnP records without changing audio routing.

    Windows does not provide a small stdlib binding for IMMDevice/WASAPI. The
    PnP AudioEndpoint class is nevertheless the OS-owned endpoint inventory;
    it includes both render and capture endpoints and their driver state.
    """
    script = r"""
$ErrorActionPreference = 'Stop'
$endpointCommand = Get-Command Get-PnpDevice -ErrorAction SilentlyContinue
if (-not $endpointCommand) { throw 'Get-PnpDevice is unavailable' }
$devices = @(Get-PnpDevice -Class AudioEndpoint -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{
    FriendlyName = $_.FriendlyName; InstanceId = $_.InstanceId; Status = $_.Status;
    Class = $_.Class; Problem = $_.Problem
  }
})
$drivers = @{}
foreach ($device in $devices) {
  try {
    $version = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction Stop).Data
    $provider = (Get-PnpDeviceProperty -InstanceId $device.InstanceId -KeyName 'DEVPKEY_Device_DriverProvider' -ErrorAction Stop).Data
    $drivers[$device.InstanceId] = [pscustomobject]@{ version = $version; provider = $provider }
  } catch { $drivers[$device.InstanceId] = [pscustomobject]@{} }
}
$microphone = [pscustomobject]@{ status = 'unknown'; value = $null; detail = $null }
try {
  $consent = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone' -ErrorAction Stop
  $microphone = [pscustomobject]@{ status = 'available'; value = $consent.Value; detail = 'Windows user-level microphone consent default' }
} catch {
  $microphone = [pscustomobject]@{ status = 'unknown'; value = $null; detail = 'No readable user-level microphone consent default' }
}
[pscustomobject]@{ endpoints = $devices; drivers = $drivers; microphone = $microphone } | ConvertTo-Json -Depth 5 -Compress
"""
    probe = _run_json_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], "windows.pnp.audioendpoint")
    if probe["status"] != "available":
        if probe["errors"] and "access" in probe["errors"][0]["message"].lower():
            probe["status"] = "denied"
        return probe
    raw = probe["data"] or {}
    records = raw.get("endpoints") or []
    if isinstance(records, dict):
        records = [records]
    drivers = raw.get("drivers") or {}
    microphone = raw.get("microphone") if isinstance(raw.get("microphone"), dict) else {}
    endpoints: list[dict[str, Any]] = []
    for record in records:
        instance_id = record.get("InstanceId")
        # MMDEVAPI endpoint instance IDs use 0.0.0 for render and 0.0.1 for capture.
        lowered = (instance_id or "").lower()
        direction = "capture" if "{0.0.1." in lowered else "render" if "{0.0.0." in lowered else "unknown"
        endpoints.append(_endpoint(
            record.get("FriendlyName"), direction, identifier=instance_id,
            state=record.get("Status"), driver=drivers.get(instance_id, {}),
            metadata={"pnp_class": record.get("Class"), "pnp_problem_code": record.get("Problem")},
        ))
    role_probe = _windows_default_endpoint_roles()
    raw_roles = role_probe.get("data") if role_probe.get("status") == "available" else {}
    raw_roles = raw_roles if isinstance(raw_roles, dict) else {}
    defaults: dict[str, Any] = {"status": role_probe.get("status", "unknown"), "console": {"render": None, "capture": None}, "multimedia": {"render": None, "capture": None}, "communications": {"render": None, "capture": None}}
    for raw_role, raw_identifier in raw_roles.items():
        if not isinstance(raw_identifier, str):
            continue
        flow, role = raw_role.split("_", 1)
        direction = "render" if flow == "render" else "capture"
        # IMMDevice IDs and PnP IDs use different separators but retain the
        # endpoint's stable {0.0.x...} suffix. Match only that normalized key.
        normalized = raw_identifier.replace("#", "\\").casefold()
        match = next((endpoint for endpoint in endpoints if normalized in str(endpoint.get("identifier") or "").replace("#", "\\").casefold()), None)
        if match is not None:
            match["default_roles"].append(role)
            defaults[role][direction] = match.get("name")
        else:
            defaults[role][direction] = "<unmatched endpoint>"
    format_probe = _windows_default_endpoint_formats() if include_endpoint_formats else None
    formats = {
        "status": "not_requested" if format_probe is None else format_probe.get("status", "unknown"),
        "default_endpoint_mix_formats": (format_probe or {}).get("data") if format_probe else {},
        "note": "GetMixFormat reports the shared-mode format of default endpoints only; it does not prove exclusive-mode, capture, or application stream compatibility.",
    }
    probe["data"] = {
        "backend": "WASAPI endpoint inventory via Windows PnP",
        "endpoints": endpoints,
        "default_roles": defaults,
        "permissions": {
            "microphone_permission": microphone.get("value"),
            "status": microphone.get("status", "unknown"),
            "scope": "Windows user-level default; individual application grants are not enumerated",
            "detail": microphone.get("detail"),
        },
        "format_capabilities": formats,
    }
    if not include_endpoint_formats:
        probe["limitations"].append("WASAPI mix formats were not queried; use --endpoint-formats for default-endpoint GetMixFormat evidence. Microphone consent is only the user-level default, not per-application capture access.")
    else:
        probe["limitations"].append("GetMixFormat is limited to default endpoint shared-mode formats; it does not test exclusive-mode or actual stream initialization. Microphone consent is only the user-level default, not per-application capture access.")
    if role_probe["status"] != "available":
        probe["limitations"].append("IMMDevice default-role probe was unavailable; inspect its status in default_roles.")
    return probe


def _macos_audio_backend() -> dict[str, Any]:
    probe = _run_json_command(["system_profiler", "SPAudioDataType", "-json"], "macos.system_profiler.SPAudioDataType", timeout=20)
    if probe["status"] != "available":
        return probe
    items = (probe["data"] or {}).get("SPAudioDataType") or []
    endpoints: list[dict[str, Any]] = []
    defaults: dict[str, Any] = {"status": "unknown", "console": None, "multimedia": None, "communications": None, "default_render": None, "default_capture": None}

    def _strings(value: Any) -> list[str]:
        if isinstance(value, dict):
            return [str(part) for key, item in value.items() for part in ([key] + _strings(item))]
        if isinstance(value, list):
            return [part for item in value for part in _strings(item)]
        return [str(value)]

    def _default_direction(value: dict[str, Any], fallback: str) -> str | None:
        for key, item in value.items():
            label = str(key).casefold().replace("_", " ")
            text = " ".join(_strings(item)).casefold()
            if "default" in label and text in {"yes", "true", "1"}:
                return "capture" if any(word in label for word in ("input", "capture", "source")) else "render" if any(word in label for word in ("output", "render", "sink")) else fallback
        return None

    def _formats(value: dict[str, Any]) -> dict[str, Any]:
        values = _strings(value)
        rates = sorted({int(match.group(1)) for text in values for match in re.finditer(r"\\b(\\d{4,6})\\s*hz\\b", text, re.I)})
        channels = sorted({int(match.group(1)) for text in values for match in re.finditer(r"\\b(\\d{1,2})\s*(?:ch|channels?)\\b", text, re.I)})
        return {"sample_rates_hz": rates, "channel_counts": channels, "sample_formats": [], "channel_layouts": []}
    for item in items:
        # system_profiler's schema varies by macOS release; preserve unknown facts.
        name = item.get("_name") or item.get("_name_localized")
        outputs = item.get("_items") or []
        if not outputs:
            endpoint = _endpoint(name, "unknown", formats=_formats(item), metadata={"system_profiler": item})
            endpoints.append(endpoint)
            continue
        for child in outputs:
            child_name = child.get("_name") or name
            text = json.dumps(child, sort_keys=True).lower()
            direction = "capture" if "input" in text and "output" not in text else "render"
            endpoint = _endpoint(child_name, direction, formats=_formats(child), metadata={"system_profiler": child})
            default_direction = _default_direction(child, direction)
            if default_direction:
                endpoint["default_roles"].append("default_%s" % default_direction)
                defaults["default_%s" % default_direction] = child_name
                defaults["status"] = "available"
            endpoints.append(endpoint)
    probe["data"] = {
        "backend": "CoreAudio inventory via system_profiler",
        "endpoints": endpoints,
        "default_roles": defaults,
        "permissions": {"microphone_permission": "unknown"},
        "format_capabilities": {"status": "unknown", "note": "No AudioObject/AudioUnit was opened; formats and layouts are only present when system_profiler supplied them in endpoint metadata."},
    }
    probe["limitations"].append("This passive CoreAudio inventory does not establish microphone permission or open AudioObject devices.")
    return probe


def _pipewire_audio_backend() -> dict[str, Any]:
    probe = _run_json_command(["pw-dump"], "pipewire.pw-dump", timeout=15)
    if probe["status"] != "available":
        return probe
    records = probe["data"] if isinstance(probe["data"], list) else []
    endpoints: list[dict[str, Any]] = []
    defaults: dict[str, Any] = {
        "status": "unknown", "console": None, "multimedia": None,
        "communications": None, "default_render": None, "default_capture": None,
    }
    for record in records:
        info = record.get("info") or {}
        props = info.get("props") or record.get("props") or {}
        if record.get("type") == "PipeWire:Interface:Metadata":
            for entry in info.get("items") or []:
                key = entry.get("key") or ""
                if key in {"default.audio.sink", "default.audio.source"}:
                    try:
                        value = json.loads(entry.get("value") or "{}")
                    except json.JSONDecodeError:
                        value = entry.get("value")
                    role = "default_render" if key.endswith("sink") else "default_capture"
                    defaults[role] = value.get("name") if isinstance(value, dict) else value
                    defaults["status"] = "available"
            continue
        media_class = props.get("media.class", "")
        if media_class not in {"Audio/Sink", "Audio/Source"}:
            continue
        direction = "render" if media_class == "Audio/Sink" else "capture"
        channels = props.get("audio.channels")
        layout = props.get("audio.position")
        sample_rate = props.get("audio.rate")
        formats = {
            "sample_rates_hz": [sample_rate] if sample_rate is not None else [],
            "sample_formats": [props["audio.format"]] if props.get("audio.format") else [],
            "channel_layouts": [layout] if layout else [],
        }
        endpoints.append(_endpoint(
            props.get("node.description") or props.get("node.nick") or props.get("node.name"), direction,
            identifier=str(record.get("id")) if record.get("id") is not None else props.get("object.serial"),
            state=info.get("state"), formats=formats,
            metadata={"media_class": media_class, "node_name": props.get("node.name"), "factory_name": props.get("factory.name")},
        ))
    for endpoint in endpoints:
        if endpoint["direction"] == "render" and endpoint["metadata"].get("node_name") == defaults["default_render"]:
            endpoint["default_roles"].append("default_render")
        if endpoint["direction"] == "capture" and endpoint["metadata"].get("node_name") == defaults["default_capture"]:
            endpoint["default_roles"].append("default_capture")
    probe["data"] = {
        "backend": "PipeWire registry snapshot",
        "endpoints": endpoints,
        "default_roles": defaults,
        "permissions": {"microphone_permission": "unknown", "note": "Portal/application capture grants are not inferred from the daemon registry."},
    }
    return probe


def _pulseaudio_audio_backend() -> dict[str, Any]:
    executable = shutil.which("pactl")
    if not executable:
        return _probe("unavailable", "pulseaudio.pactl", errors=[_error("tool_not_found", "pactl")])
    def query(kind: str) -> tuple[Any, str | None]:
        try:
            result = subprocess.run([executable, "-f", "json", "list", kind], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
            if result.returncode:
                return None, result.stderr.strip() or "pactl returned %s" % result.returncode
            return json.loads(result.stdout), None
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            return None, str(exc)
    sinks, sink_error = query("sinks")
    sources, source_error = query("sources")
    server, server_error = query("server")
    if sink_error and source_error:
        return _probe("failed", "pulseaudio.pactl", errors=[_error("query_failed", sink_error + "; " + source_error)])
    endpoints: list[dict[str, Any]] = []
    for direction, records in (("render", sinks or []), ("capture", sources or [])):
        for record in records:
            sample_spec = record.get("sample_spec") or ""
            match = re.search(r"(\d+)Hz", sample_spec)
            channels = record.get("channel_map")
            endpoints.append(_endpoint(
                record.get("description") or record.get("name"), direction,
                identifier=record.get("name"), state=record.get("state"),
                formats={"sample_rates_hz": [int(match.group(1))] if match else [], "sample_formats": [sample_spec.split()[0]] if sample_spec else [], "channel_layouts": [channels] if channels else []},
                metadata={"mute": record.get("mute"), "monitor_source": record.get("monitor_source_name")},
            ))
    default_sink = (server or {}).get("default_sink_name")
    default_source = (server or {}).get("default_source_name")
    defaults = {
        "status": "available" if server else "unknown", "console": None,
        "multimedia": None, "communications": None, "default_render": default_sink,
        "default_capture": default_source,
    }
    for endpoint in endpoints:
        if endpoint["direction"] == "render" and endpoint["identifier"] == default_sink:
            endpoint["default_roles"].append("default_render")
        if endpoint["direction"] == "capture" and endpoint["identifier"] == default_source:
            endpoint["default_roles"].append("default_capture")
    return _probe("available", "pulseaudio.pactl", data={
        "backend": "PulseAudio server inventory",
        "endpoints": endpoints,
        "default_roles": defaults,
        "permissions": {"microphone_permission": "unknown"},
    }, errors=[_error("server_query_failed", server_error)] if server_error else [])


def _alsa_audio_backend() -> dict[str, Any]:
    cards_path = Path("/proc/asound/cards")
    pcm_path = Path("/proc/asound/pcm")
    if not cards_path.exists():
        return _probe("unavailable", "linux.alsa.procfs", errors=[_error("procfs_missing", str(cards_path))])
    try:
        cards = cards_path.read_text(encoding="utf-8", errors="replace").splitlines()
        pcm = pcm_path.read_text(encoding="utf-8", errors="replace").splitlines() if pcm_path.exists() else []
    except OSError as exc:
        return _probe("denied", "linux.alsa.procfs", errors=[_error("read_failed", str(exc))])
    endpoints: list[dict[str, Any]] = []
    for line in pcm:
        match = re.match(r"\s*(\d+)-(\d+):\s*(.*?)\s*:\s*(.*)$", line)
        if not match:
            continue
        card, device, name, capabilities = match.groups()
        lowered = capabilities.lower()
        for direction, marker in (("render", "playback"), ("capture", "capture")):
            if marker in lowered:
                endpoints.append(_endpoint(name, direction, identifier="hw:%s,%s" % (card, device), metadata={"alsa_capabilities": capabilities}))
    return _probe("available", "linux.alsa.procfs", data={
        "backend": "ALSA procfs inventory",
        "cards": cards,
        "endpoints": endpoints,
        "default_roles": {"status": "unknown", "console": None, "multimedia": None, "communications": None},
        "permissions": {"microphone_permission": "not_applicable", "note": "ALSA access is normally device-node ACL based; this passive procfs inventory does not attempt an open."},
    })


def _collect_os_audio(include_endpoint_formats: bool = False) -> dict[str, Any]:
    system = platform.system()
    if system == "Windows":
        return {"wasapi": _windows_audio_backend(include_endpoint_formats=include_endpoint_formats)}
    if system == "Darwin":
        return {"coreaudio": _macos_audio_backend()}
    if system == "Linux":
        return {"pipewire": _pipewire_audio_backend(), "pulseaudio": _pulseaudio_audio_backend(), "alsa": _alsa_audio_backend()}
    return {"platform_audio": _probe("unsupported", "platform.dispatch", limitations=["No OS audio backend is implemented for %s." % system])}


def collect_audio_info(
    probe_context: bool = True,
    include_openal_info: bool = False,
    include_os_audio: bool = True,
    include_endpoint_formats: bool = False,
    redaction: str = "none",
    smoke_test: str = "none",
) -> dict[str, Any]:
    """Return the public audio report while preserving the OpenAL subreport.

    ``audio.openal`` is the unmodified ``openal`` member returned by the
    built-in OpenAL probe. The facade's platform value is likewise copied from
    that single probe so the two cannot disagree.
    """
    openal_report = _collect_openal_info(
        probe_context=probe_context,
        include_openal_info=include_openal_info,
    )
    report = {
        "schema_version": SCHEMA_VERSION,
        "platform": openal_report["platform"],
        "audio": {
            "openal": openal_report["openal"],
            "platform_backends": _collect_os_audio(include_endpoint_formats=include_endpoint_formats) if include_os_audio else {},
            "smoke_tests": [],
        },
    }
    if smoke_test == "openal-default-context":
        context = report["audio"]["openal"]["context"]
        available = report["audio"]["openal"].get("available")
        report["audio"]["smoke_tests"].append({
            "name": smoke_test,
            "requested": True,
            "status": "passed" if context.get("created") else "unavailable" if not available else "failed",
            "tested": "Requested an OpenAL default-context open/close probe; it never renders audio or captures microphone input.",
            "evidence": {"runtime_available": available, "context_attempted": context.get("attempted"), "context_created": context.get("created"), "failure": context.get("failure") or ("OpenAL runtime was unavailable; no context open was attempted." if not available else None)},
        })
    if redaction != "none":
        # Device labels can embed a person's name (for example Bluetooth
        # headsets), so audio metadata gets stricter treatment than generic
        # host reports. Common finalization additionally handles paths/IDs.
        report["audio"] = _redact_audio_metadata(report["audio"], redaction)
    return report


def _llm_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Produce bounded capability facts without relaying raw native dumps."""
    audio = report.get("audio", {})
    openal = audio.get("openal", {})
    context = openal.get("context", {})
    backend_summary: dict[str, Any] = {}
    overall = "available" if openal.get("available") else "unknown"
    for name, backend in audio.get("platform_backends", {}).items():
        data = backend.get("data") or {}
        endpoints = data.get("endpoints") or []
        backend_summary[name] = {
            "status": backend.get("status", "unknown"),
            "source": (backend.get("provenance") or {}).get("source"),
            "render_endpoint_count": sum(1 for endpoint in endpoints if endpoint.get("direction") == "render"),
            "capture_endpoint_count": sum(1 for endpoint in endpoints if endpoint.get("direction") == "capture"),
            "default_roles": data.get("default_roles"),
            "capture_permission": data.get("permissions"),
            "format_capabilities": data.get("format_capabilities"),
            "error_codes": [error.get("code") for error in backend.get("errors", [])],
        }
        if backend.get("status") == "available":
            overall = "available"
    return {
        "status": overall,
        "openal": {
            "status": "available" if openal.get("available") else "unavailable",
            "library_loaded": bool((openal.get("library") or {}).get("loaded_path")),
            "default_device": (openal.get("global") or {}).get("default_device"),
            "context_created": context.get("created"),
            "context_failure": context.get("failure"),
        },
        "platform_backends": backend_summary,
        "smoke_tests": audio.get("smoke_tests", []),
    }


def _print_human(report: dict[str, Any]) -> None:
    """Print a concise summary; use --json for the full nested report."""
    openal = report["audio"]["openal"]
    library = openal["library"]
    global_data = openal["global"]
    context = openal["context"]
    al = context.get("details", {}).get("al", {})

    print("Audio capabilities")
    print("OpenAL: %s" % ("available" if openal["available"] else "not available"))
    print("Library: %s" % (library.get("loaded_path") or "not loaded"))
    print("Default device: %s" % (global_data.get("default_device") or "not reported"))
    print(
        "Devices (%d): %s"
        % (
            len(global_data.get("devices", [])),
            "; ".join(global_data.get("devices", [])) or "not enumerated",
        )
    )
    print(
        "Context: %s"
        % (
            "created"
            if context.get("created")
            else context.get("failure") or "not requested"
        )
    )
    print("Renderer: %s" % (al.get("renderer") or "not reported"))
    for limitation in openal.get("limitations", []):
        print("Note: %s" % limitation)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report OpenAL plus locally observable operating-system audio endpoint information."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the stable JSON report instead of a concise human summary",
    )
    parser.add_argument(
        "--no-context",
        action="store_true",
        help="do not open and immediately close the default audio device",
    )
    parser.add_argument(
        "--include-openal-info",
        action="store_true",
        help="also capture output from the optional native openal-info utility",
    )
    parser.add_argument(
        "--no-os-audio",
        action="store_true",
        help="skip passive WASAPI/CoreAudio/PipeWire/PulseAudio/ALSA inventory",
    )
    parser.add_argument(
        "--endpoint-formats",
        action="store_true",
        help="on Windows, activate IAudioClient only long enough to read default-endpoint shared mix formats",
    )
    parser.add_argument(
        "--smoke-test",
        choices=("none", "openal-default-context"),
        default="none",
        help="explicit safe smoke test; default runs none (openal-default-context never renders/captures)",
    )
    add_common_arguments(parser)
    args = parser.parse_args()
    if args.output_schema:
        print(json.dumps(requirements_schema(), indent=2, sort_keys=True))
        return 0
    if args.report_schema:
        print(json.dumps(report_schema(), indent=2, sort_keys=True))
        return 0
    # An explicit smoke test takes precedence over --no-context solely for its
    # named test; ordinary default behavior remains unchanged.
    report = collect_audio_info(
        probe_context=not args.no_context or args.smoke_test == "openal-default-context",
        include_openal_info=args.include_openal_info,
        include_os_audio=not args.no_os_audio,
        include_endpoint_formats=args.endpoint_formats,
        redaction=args.redact,
        smoke_test=args.smoke_test,
    )
    report = finalize_report(report, args, "audio_info", _llm_summary)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str, allow_nan=False))
    else:
        if args.profile == "full":
            _print_human(report)
        else:
            print(json.dumps(report["summary"], indent=2, sort_keys=True, default=str, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
