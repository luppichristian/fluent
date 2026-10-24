#!/usr/bin/env python3
"""Combine the system, hardware, and CPU diagnostic collectors in one CLI."""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


# This file deliberately embeds the transport helpers instead of importing a
# sibling module: diagnostic scripts must remain usable after being copied out
# of this repository.  Keep the command-line contract aligned with the other
# collectors, but do not make this executable depend on its launch directory.
_COMMON_STATUS_VALUES = ("available", "unsupported", "unavailable", "denied", "failed", "unknown")
_REDACTION_LEVELS = ("none", "default", "strict")


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", choices=("full", "llm", "summary"), default="full", help="output view: full evidence (default), bounded LLM view, or compact summary")
    parser.add_argument("--redact", choices=_REDACTION_LEVELS, default="none", help="replace sensitive local identifiers before output or saving (default: none for compatibility)")
    parser.add_argument("--requirements", metavar="PATH", help="evaluate a JSON requirements manifest against this report")
    parser.add_argument("--compare", metavar="PATH", help="compare the report with a prior JSON snapshot")
    parser.add_argument("--save", metavar="PATH", help="write the final JSON report to a snapshot file")
    parser.add_argument("--envelope", action="store_true", help="wrap full evidence in the common tool/status/metadata envelope")
    parser.add_argument("--output-schema", action="store_true", help="print the common requirements-manifest schema and exit")
    parser.add_argument("--report-schema", action="store_true", help="print the machine-report JSON Schema and exit")


def requirements_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://fluent.local/schemas/diagnostic-requirements-1.json",
        "schema_version": 1,
        "type": "object",
        "required": ["requirements"],
        "properties": {"requirements": {"type": "array", "items": {"type": "object", "required": ["path"], "properties": {"id": {"type": "string"}, "path": {"type": "string"}, "operator": {"enum": ["exists", "equals", "not_equals", "contains", "gte", "lte"]}, "description": {"type": "string"}}}}},
        "description": "A requirements manifest is an object containing a requirements array.",
        "requirement": {"id": "stable human-readable identifier", "path": "dot path in the emitted full report; list indexes use [0]", "operator": ["exists", "equals", "not_equals", "contains", "gte", "lte"], "value": "required except for exists", "description": "optional explanation shown in the result"},
        "status_values": list(_COMMON_STATUS_VALUES),
        "example": {"requirements": [{"id": "logical-cpus", "path": "sections.cpu.cpu.logical_cores", "operator": "gte", "value": 8}]},
    }


def report_schema() -> dict[str, Any]:
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "https://fluent.local/schemas/machine-info-report-1.json", "title": "Fluent machine_info report", "oneOf": [{"type": "object", "required": ["schema_version", "platform", "selected_sections", "sections"], "properties": {"schema_version": {"type": "integer", "const": 1}, "platform": {"type": "object"}, "selected_sections": {"type": "array", "items": {"enum": ["system", "hardware", "cpu"]}}, "sections": {"type": "object"}}, "additionalProperties": True}, {"type": "object", "required": ["schema_version", "tool", "status", "metadata", "data"], "properties": {"schema_version": {"type": "integer", "const": 1}, "tool": {"const": "machine_info"}, "status": {"type": "string"}, "metadata": {"type": "object"}, "data": {"type": "object"}}, "additionalProperties": True}]}


def _redacted(value: Any) -> str:
    return "<redacted:%s>" % hashlib.sha256(str(value).encode("utf-8", errors="replace")).hexdigest()[:12]


def _sensitive_key(key: str, level: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    default = ("serial", "uuid", "mac", "ip", "address", "addresses", "id", "hostname", "fqdn", "username", "qualified_name", "home", "path", "pnp_device_id", "pci_bus_id", "device_id", "executable", "working_directory")
    strict = default + ("name", "model", "manufacturer", "vendor", "driver", "group", "environment", "variables")
    # Match complete field components: ``mac_address`` is sensitive, while
    # ``machine`` must remain a structural platform/status field.
    return any(normalized == token or normalized.startswith(token + "_") or normalized.endswith("_" + token) for token in (strict if level == "strict" else default))


def _path_is_sensitive(path: str, level: str) -> bool:
    """Recognize a report path without needing to resolve its possibly-redacted value."""
    return any(_sensitive_key(part, level) for part in re.split(r"[.\[\]]+", path) if part)


def _redact(value: Any, level: str, sensitive: bool = False) -> Any:
    """Redact scalar leaves while preserving every object/list container."""
    if level == "none":
        return copy.deepcopy(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        report_path = value.get("path")
        is_reference_entry = isinstance(report_path, str) and (
            "operator" in value or "before" in value or "after" in value
        )
        for key, item in value.items():
            # Compatibility and comparison entries retain a source path next to
            # the copied raw value.  That source controls sensitivity of the
            # value even though keys such as "actual" and "before" are generic.
            path_sensitive = (
                key in {"actual", "before", "after"}
                and isinstance(report_path, str)
                and _path_is_sensitive(report_path, level)
            )
            # Manifest result ``id`` and its symbolic ``path`` are stable
            # labels, not collected machine identifiers.
            key_sensitive = _sensitive_key(str(key), level) and not (key in {"path", "id"} and is_reference_entry)
            result[key] = _redact(item, level, sensitive or key_sensitive or path_sensitive)
        return result
    if isinstance(value, list):
        return [_redact(item, level, sensitive) for item in value]
    return _redacted(value) if sensitive and value not in (None, "") else value


def _resolve_path(document: Any, path: str) -> tuple[bool, Any]:
    current = document
    for raw in path.split("."):
        match = re.fullmatch(r"([^\[]+)?(?:\[(\d+)\])?", raw)
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


def _evaluate_requirements(report: dict[str, Any], path: str) -> dict[str, Any]:
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"status": "failed", "manifest": path, "error": str(error), "results": []}
    entries = manifest.get("requirements") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return {"status": "failed", "manifest": path, "error": "manifest must contain a requirements array", "results": []}
    results: list[dict[str, Any]] = []
    operators = {"exists", "equals", "not_equals", "contains", "gte", "lte"}
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            results.append({"id": "requirement-%d" % index, "status": "failed", "error": "requirement needs a string path"})
            continue
        exists, actual = _resolve_path(report, item["path"])
        operator, expected = item.get("operator", "exists"), item.get("value")
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
            elif operator not in operators:
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


def _compare_snapshot(report: dict[str, Any], path: str, maximum_changes: int = 200) -> dict[str, Any]:
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
            for item in value.values(): comparable(item)
        elif isinstance(value, list):
            for item in value: comparable(item)
        return value
    before, after = _flatten(comparable(prior)), _flatten(comparable(report))
    def change_kind(key: str) -> str:
        if key not in before: return "added"
        if key not in after: return "removed"
        old, new = before[key], after[key]
        if (old is True and new is False) or (isinstance(old, (int, float)) and not isinstance(old, bool) and isinstance(new, (int, float)) and not isinstance(new, bool) and new < old): return "regressed"
        if isinstance(old, str) and isinstance(new, str) and old in {"available", "passed"} and new in {"unavailable", "unsupported", "denied", "failed"}: return "regressed"
        return "changed"
    changes = [{"path": key, "before": before.get(key), "after": after.get(key), "kind": change_kind(key)} for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)]
    return {"status": "changed" if changes else "unchanged", "snapshot": path, "change_count": len(changes), "truncated": len(changes) > maximum_changes, "changes": changes[:maximum_changes]}


def finalize_report(report: dict[str, Any], args: argparse.Namespace, tool: str, summary: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    """Apply standalone LLM, privacy, requirement, and snapshot controls."""
    enhanced = any((args.profile != "full", args.redact != "none", args.requirements, args.compare, args.save, args.envelope))
    if not enhanced:
        return copy.deepcopy(report)
    enriched = copy.deepcopy(report)
    enriched.setdefault("metadata", {})
    enriched["metadata"].update({"tool": tool, "collected_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "redaction": args.redact})
    if args.requirements:
        enriched["compatibility"] = _evaluate_requirements(enriched, args.requirements)
    if args.compare:
        enriched["comparison"] = _compare_snapshot(enriched, args.compare)
    redacted = _redact(enriched, args.redact)
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


# Collector implementations are intentionally nested in factories.  This keeps
# similarly named platform helpers isolated after the former standalone tools
# were consolidated into this one self-contained entry point.

def _build_system_collector():
    import argparse
    import csv
    import ctypes
    import datetime as dt
    import getpass
    import json
    import locale
    import os
    import platform
    import re
    import shutil
    import socket
    import subprocess
    import sys
    import time
    from pathlib import Path
    from typing import Any
    _STARTED_MONOTONIC = time.monotonic()
    _STARTED_AT = dt.datetime.now(dt.timezone.utc)
    _REDACTED = "***REDACTED***"
    _SENSITIVE_ENVIRONMENT_NAME = re.compile(
        r"(?:api[_-]?key|auth(?:orization)?|bearer|cookie|credential|pass(?:word)?|private|secret|session|token|(?:^|[_-])key(?:$|[_-])|(?:^|[_-])(?:https?[_-]?)?proxy(?:$|[_-])|(?:^|[_-])(?:dsn|connection(?:[_-]?string)?|database[_-]?(?:url|uri))(?:$|[_-]))",
        re.IGNORECASE,
    )
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    def _run(*command: str) -> str | None:
        """Run one fixed optional OS command without propagating probe failures."""
        if not shutil.which(command[0]):
            return None
        try:
            return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            return None
    def _as_int(value: str | int | None) -> int | None:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None
    def _iso_utc(timestamp: float | int | None) -> str | None:
        if timestamp is None:
            return None
        try:
            return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError):
            return None
    def _parse_key_value_lines(text: str, separator: str = "=") -> dict[str, str]:
        values: dict[str, str] = {}
        for line in text.splitlines():
            if separator not in line:
                continue
            key, value = line.split(separator, 1)
            values[key.strip()] = value.strip().strip('"')
        return values
    def _linux_release() -> dict[str, str | None]:
        values = _parse_key_value_lines(_read_text(Path("/etc/os-release")) or "")
        return {
            "name": values.get("NAME"),
            "pretty_name": values.get("PRETTY_NAME"),
            "version_id": values.get("VERSION_ID"),
            "id": values.get("ID"),
        }
    def _macos_release() -> dict[str, str | None]:
        values = _parse_key_value_lines(_run("sw_vers") or ":", ":")
        return {
            "name": values.get("ProductName"),
            "pretty_name": values.get("ProductName"),
            "version_id": values.get("ProductVersion"),
            "id": "macos",
        }
    def _windows_release() -> dict[str, str | None]:
        edition = None
        try:
            edition = platform.win32_edition() or None
        except AttributeError:
            pass
        return {
            "name": "Windows",
            "pretty_name": " ".join(part for part in ("Windows", edition) if part),
            "version_id": platform.version() or None,
            "id": "windows",
        }
    def _operating_system() -> dict[str, Any]:
        system = platform.system() or None
        if system == "Linux":
            distribution = _linux_release()
        elif system == "Darwin":
            distribution = _macos_release()
        elif system == "Windows":
            distribution = _windows_release()
        else:
            distribution = {"name": system, "pretty_name": system, "version_id": None, "id": None}
        return {
            "family": system,
            "distribution": distribution,
            "kernel_release": platform.release() or None,
            "kernel_version": platform.version() or None,
            "machine": platform.machine() or None,
            "architecture": platform.architecture()[0] or None,
        }
    def _linux_boot() -> tuple[float | None, float | None]:
        stat = _read_text(Path("/proc/stat")) or ""
        boot = None
        for line in stat.splitlines():
            if line.startswith("btime "):
                boot = _as_int(line.split(maxsplit=1)[1])
                break
        uptime_text = _read_text(Path("/proc/uptime")) or ""
        try:
            uptime = float(uptime_text.split()[0])
        except (IndexError, ValueError):
            uptime = None
        return boot, uptime
    def _macos_boot() -> tuple[float | None, float | None]:
        raw = _run("sysctl", "-n", "kern.boottime") or ""
        match = re.search(r"sec\s*=\s*(\d+)", raw)
        boot = float(match.group(1)) if match else None
        return boot, max(0.0, time.time() - boot) if boot is not None else None
    def _windows_boot() -> tuple[float | None, float | None]:
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.GetTickCount64.restype = ctypes.c_ulonglong
            uptime = kernel32.GetTickCount64() / 1000
            return time.time() - uptime, uptime
        except (AttributeError, OSError):
            return None, None
    def _boot() -> dict[str, Any]:
        if sys.platform.startswith("linux"):
            boot, uptime = _linux_boot()
        elif sys.platform == "darwin":
            boot, uptime = _macos_boot()
        elif sys.platform == "win32":
            boot, uptime = _windows_boot()
        else:
            boot, uptime = None, None
        return {"boot_time_utc": _iso_utc(boot), "uptime_seconds": round(uptime, 3) if uptime is not None else None}
    def _linux_memory() -> dict[str, int | None]:
        values = _parse_key_value_lines(_read_text(Path("/proc/meminfo")) or ":", ":")

        def kib(name: str) -> int | None:
            value = values.get(name)
            if not value:
                return None
            parsed = _as_int(value.split(maxsplit=1)[0])
            return parsed * 1024 if parsed is not None else None

        total = kib("MemTotal")
        available = kib("MemAvailable")
        return {"total_bytes": total, "available_bytes": available, "used_bytes": total - available if total is not None and available is not None else None}
    def _macos_memory() -> dict[str, int | None]:
        value = _run("sysctl", "-n", "hw.memsize")
        return {"total_bytes": _as_int(value.strip()) if value else None, "available_bytes": None, "used_bytes": None}
    def _windows_memory() -> dict[str, int | None]:
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        try:
            status = MemoryStatus()
            status.dwLength = ctypes.sizeof(status)
            if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return {"total_bytes": None, "available_bytes": None, "used_bytes": None}
            return {"total_bytes": status.ullTotalPhys, "available_bytes": status.ullAvailPhys, "used_bytes": status.ullTotalPhys - status.ullAvailPhys}
        except (AttributeError, OSError):
            return {"total_bytes": None, "available_bytes": None, "used_bytes": None}
    def _resources() -> dict[str, Any]:
        if sys.platform.startswith("linux"):
            memory = _linux_memory()
        elif sys.platform == "darwin":
            memory = _macos_memory()
        elif sys.platform == "win32":
            memory = _windows_memory()
        else:
            memory = {"total_bytes": None, "available_bytes": None, "used_bytes": None}
        try:
            loads = os.getloadavg()
            load_average: dict[str, float | None] = {"1m": loads[0], "5m": loads[1], "15m": loads[2]}
        except (AttributeError, OSError):
            load_average = {"1m": None, "5m": None, "15m": None}
        try:
            usage = shutil.disk_usage(Path.cwd())
            filesystem = {"path": str(Path.cwd()), "total_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}
        except OSError:
            filesystem = {"path": str(Path.cwd()), "total_bytes": None, "used_bytes": None, "free_bytes": None}
        return {"memory": memory, "load_average": load_average, "working_directory_filesystem": filesystem}
    def _network() -> dict[str, Any]:
        hostname = socket.gethostname() or None
        fqdn = socket.getfqdn() or None
        addresses: set[str] = set()
        if hostname:
            try:
                addresses.update(socket.gethostbyname_ex(hostname)[2])
            except socket.gaierror:
                pass
        return {"hostname": hostname, "fqdn": fqdn, "addresses": sorted(addresses)}
    def _locale() -> dict[str, Any]:
        try:
            language, encoding = locale.getlocale()
        except (ValueError, locale.Error):
            language, encoding = None, None
        try:
            preferred_encoding = locale.getencoding()
        except AttributeError:
            preferred_encoding = locale.getpreferredencoding(False)
        local_now = dt.datetime.now().astimezone()
        offset = local_now.utcoffset()
        return {
            "language": language,
            "encoding": encoding,
            "preferred_encoding": preferred_encoding or None,
            "timezone": local_now.tzname(),
            "utc_offset_seconds": int(offset.total_seconds()) if offset else 0,
        }
    def _is_administrator() -> bool | None:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        if sys.platform == "win32":
            try:
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                return None
        return None
    def _unix_identity() -> dict[str, Any]:
        try:
            import grp
            import pwd
        except ImportError:
            return {"username": getpass.getuser() or None, "uid": None, "gid": None, "groups": [], "home": str(Path.home()), "is_administrator": _is_administrator()}
        uid = os.getuid()
        gid = os.getgid()
        try:
            account = pwd.getpwuid(uid)
            username, home = account.pw_name, account.pw_dir
        except KeyError:
            username, home = getpass.getuser() or None, str(Path.home())
        groups: list[dict[str, int | str]] = []
        for group_id in sorted(set(os.getgroups()) | {gid}):
            try:
                groups.append({"name": grp.getgrgid(group_id).gr_name, "id": group_id})
            except KeyError:
                groups.append({"name": str(group_id), "id": group_id})
        return {"username": username, "uid": uid, "gid": gid, "groups": groups, "home": home or None, "is_administrator": _is_administrator()}
    def _windows_groups() -> list[dict[str, str | None]]:
        raw = _run("whoami", "/groups", "/fo", "csv", "/nh")
        if not raw:
            return []
        groups: list[dict[str, str | None]] = []
        try:
            for row in csv.reader(raw.splitlines()):
                if not row or not row[0].strip():
                    continue
                groups.append({"name": row[0].strip(), "type": row[1].strip() if len(row) > 1 else None})
        except csv.Error:
            return []
        return groups
    def _windows_identity() -> dict[str, Any]:
        username = getpass.getuser() or None
        raw = _run("whoami")
        qualified_name = raw.strip() if raw else username
        return {"username": username, "qualified_name": qualified_name, "uid": None, "gid": None, "groups": _windows_groups(), "home": str(Path.home()), "is_administrator": _is_administrator()}
    def _identity() -> dict[str, Any]:
        return _windows_identity() if sys.platform == "win32" else _unix_identity()
    def _process() -> dict[str, Any]:
        parent = os.getppid() if hasattr(os, "getppid") else None
        return {
            "pid": os.getpid(),
            "parent_pid": parent,
            "runtime_seconds": round(time.monotonic() - _STARTED_MONOTONIC, 6),
            "started_at_utc": _STARTED_AT.isoformat().replace("+00:00", "Z"),
            "working_directory": str(Path.cwd()),
            "executable": sys.executable or None,
            "python": {
                "implementation": platform.python_implementation(),
                "version": platform.python_version(),
                "prefix": sys.prefix,
                "in_virtual_environment": sys.prefix != getattr(sys, "base_prefix", sys.prefix),
            },
        }
    def _environment() -> dict[str, Any]:
        variables: dict[str, str] = {}
        redacted = 0
        for name in sorted(os.environ):
            value = os.environ[name]
            if _SENSITIVE_ENVIRONMENT_NAME.search(name):
                variables[name] = _REDACTED
                redacted += 1
            elif len(value) > 4096:
                variables[name] = value[:4096] + "… [truncated]"
            else:
                variables[name] = value
        return {"included": True, "count": len(variables), "redacted_count": redacted, "variables": variables}
    def collect_system_info(include_environment: bool = False) -> dict[str, Any]:
        """Collect a stable, JSON-serializable system and current-user report."""
        report: dict[str, Any] = {
            "operating_system": _operating_system(),
            "host": {**_network(), **_boot()},
            "resources": _resources(),
            "locale": _locale(),
            "user": _identity(),
            "process": _process(),
            "environment": {"included": False, "count": None, "redacted_count": None, "variables": None},
        }
        if include_environment:
            report["environment"] = _environment()
        return report

    return collect_system_info


collect_system_info = _build_system_collector()
del _build_system_collector

def _build_hardware_collector():
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

    return collect_hardware_info


collect_hardware_info = _build_hardware_collector()
del _build_hardware_collector

def _build_cpu_collector():
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

    return collect_cpu_info


collect_cpu_info = _build_cpu_collector()
del _build_cpu_collector


# Developer context is deliberately separate from the historic three section
# reports.  It is opt-in because command discovery and interface addresses are
# useful for a build/compatibility investigation but unnecessary for a small
# inventory call.  Every new probe keeps its evidence source and distinguishes
# no data from an unsupported or denied probe.
_STATUS_AVAILABLE = "available"
_STATUS_UNAVAILABLE = "unavailable"
_STATUS_UNSUPPORTED = "unsupported"
_STATUS_UNKNOWN = "unknown"


def _probe(status: str, source: str, value: Any = None, detail: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "source": source, "value": value}
    if detail:
        result["detail"] = detail
    return result


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip() or None
    except OSError:
        return None


def _command_version(command: tuple[str, ...]) -> dict[str, Any]:
    """Capture one fixed tool version with executable and command provenance."""
    executable = shutil.which(command[0])
    if not executable:
        return _probe(_STATUS_UNAVAILABLE, "PATH", {"command": list(command), "executable": None, "version": None})
    try:
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, check=False)
    except subprocess.TimeoutExpired:
        return _probe("failed", "subprocess", {"command": list(command), "executable": executable, "version": None}, "timed out after 4 seconds")
    except OSError as error:
        return _probe("failed", "subprocess", {"command": list(command), "executable": executable, "version": None}, str(error))
    output = (completed.stdout or completed.stderr).strip()
    first_line = output.splitlines()[0] if output else None
    return _probe(
        _STATUS_AVAILABLE if completed.returncode == 0 else "failed",
        "subprocess",
        {"command": list(command), "executable": executable, "version": first_line, "exit_code": completed.returncode},
    )


def _toolchains() -> list[dict[str, Any]]:
    # Commands are fixed, short version queries only; no shell, discovery scan,
    # package installation, or project-specific build invocation occurs.
    commands = (
        ("python", (sys.executable, "--version")),
        ("gcc", ("gcc", "--version")),
        ("clang", ("clang", "--version")),
        ("msvc-cl", ("cl",)),
        ("go", ("go", "version")),
        ("rustc", ("rustc", "--version")),
        ("cargo", ("cargo", "--version")),
        ("dotnet", ("dotnet", "--version")),
        ("java", ("java", "-version")),
        ("node", ("node", "--version")),
        ("npm", ("npm", "--version")),
        ("cmake", ("cmake", "--version")),
        ("ninja", ("ninja", "--version")),
        ("make", ("make", "--version")),
        ("pip", ("pip", "--version")),
        ("winget", ("winget", "--version")),
        ("choco", ("choco", "--version")),
        ("brew", ("brew", "--version")),
        ("apt", ("apt", "--version")),
    )
    return [{"name": name, **_command_version(command)} for name, command in commands]


def _linux_runtime_context() -> dict[str, Any]:
    release = platform.release().casefold()
    cgroup = _read_optional(Path("/proc/self/cgroup"))
    cgroup_text = (cgroup or "").casefold()
    container_markers = ("docker", "containerd", "kubepods", "podman", "lxc", "libpod")
    container = Path("/.dockerenv").exists() or any(marker in cgroup_text for marker in container_markers)
    cpu_max = _read_optional(Path("/sys/fs/cgroup/cpu.max"))
    cpu_limit: float | None = None
    if cpu_max and cpu_max != "max":
        try:
            quota, period = cpu_max.split()[:2]
            cpu_limit = int(quota) / int(period)
        except (ValueError, ZeroDivisionError):
            pass
    memory_max_text = _read_optional(Path("/sys/fs/cgroup/memory.max"))
    try:
        memory_limit = None if memory_max_text in (None, "max") else int(memory_max_text)
    except ValueError:
        memory_limit = None
    affinity: list[int] | None
    try:
        affinity = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        affinity = None
    virtual = "hypervisor" in ((_read_optional(Path("/proc/cpuinfo")) or "").casefold())
    remote = bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"))
    return {
        "container": _probe(_STATUS_AVAILABLE, "/.dockerenv,/proc/self/cgroup", container),
        "wsl": _probe(_STATUS_AVAILABLE, "platform.release", "microsoft" in release or "wsl" in release),
        "virtual_machine": _probe(_STATUS_AVAILABLE, "/proc/cpuinfo", virtual, "A false value only means the kernel did not expose the hypervisor CPU flag."),
        "remote_session": _probe(_STATUS_AVAILABLE, "SSH_CONNECTION,SSH_TTY", remote),
        "effective_limits": _probe(
            _STATUS_AVAILABLE,
            "/sys/fs/cgroup,/proc/self/status,os.sched_getaffinity",
            {"cgroup_version": 2 if Path("/sys/fs/cgroup/cgroup.controllers").exists() else None, "cpu_quota_cores": cpu_limit, "memory_limit_bytes": memory_limit, "allowed_cpu_ids": affinity},
        ),
    }


def _windows_runtime_context() -> dict[str, Any]:
    session = os.environ.get("SESSIONNAME", "")
    remote = session.upper().startswith("RDP-") or bool(os.environ.get("SSH_CONNECTION"))
    status, system, detail = _powershell_json(
        "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,HypervisorPresent | ConvertTo-Json -Compress"
    )
    virtual = None
    if status == _STATUS_AVAILABLE and isinstance(system, dict):
        manufacturer = str(system.get("Manufacturer") or "").casefold()
        model = str(system.get("Model") or "").casefold()
        virtual = bool(system.get("HypervisorPresent")) or any(token in manufacturer + " " + model for token in ("virtual", "vmware", "qemu", "xen", "kvm"))
    # WSL only runs a Linux kernel, but retain this explicit platform result so
    # a consumer never has to infer it from an absent Linux field.
    job_probe = _windows_job_limits()
    return {
        "container": _windows_container_context(),
        "wsl": _probe(_STATUS_AVAILABLE, "sys.platform", False),
        "virtual_machine": _probe(status, "PowerShell Win32_ComputerSystem", virtual, detail),
        "remote_session": _probe(_STATUS_AVAILABLE, "SESSIONNAME,SSH_CONNECTION", remote),
        "effective_limits": job_probe,
        "job_object": job_probe,
    }


def _windows_container_context() -> dict[str, Any]:
    """Report explicit Windows-container markers without treating a Job as proof."""
    markers = [name for name in ("CONTAINER_SANDBOX_MOUNT_POINT", "CONTAINER_ID", "DOTNET_RUNNING_IN_CONTAINER", "KUBERNETES_SERVICE_HOST") if os.environ.get(name)]
    registry_value: Any = None
    registry_error: str | None = None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control") as key:
            registry_value, _ = winreg.QueryValueEx(key, "ContainerType")
    except FileNotFoundError:
        pass
    except OSError as error:
        registry_error = type(error).__name__
    detected = bool(markers or registry_value)
    details = {"detected": detected, "environment_markers": markers, "container_type": registry_value}
    note = "No explicit Windows-container marker was found; this does not rule out every isolation mechanism." if not detected else None
    if registry_error:
        note = (note + " " if note else "") + "Container registry probe failed: %s." % registry_error
    return _probe(_STATUS_AVAILABLE, "environment,HKLM SYSTEM\\CurrentControlSet\\Control\\ContainerType", details, note)


def _windows_job_limits() -> dict[str, Any]:
    """Read current Windows Job Object membership and enforceable limits.

    A job is not automatically a container, but its limits govern a process in
    common local sandboxes, CI runners, and Windows-container hosts.
    """
    empty = {"in_job": None, "limit_flags": None, "active_process_limit": None,
             "process_memory_limit_bytes": None, "job_memory_limit_bytes": None,
             "cpu_time_limit_100ns": {"per_process": None, "per_job": None},
             "affinity_mask": None}
    try:
        class LargeInteger(ctypes.Structure):
            _fields_ = [("quad_part", ctypes.c_longlong)]
        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_operation_count", "write_operation_count", "other_operation_count", "read_transfer_count", "write_transfer_count", "other_transfer_count")]
        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("per_process_user_time_limit", LargeInteger), ("per_job_user_time_limit", LargeInteger),
                ("limit_flags", ctypes.c_uint32), ("minimum_working_set_size", ctypes.c_size_t),
                ("maximum_working_set_size", ctypes.c_size_t), ("active_process_limit", ctypes.c_uint32),
                ("affinity", ctypes.c_size_t), ("priority_class", ctypes.c_uint32), ("scheduling_class", ctypes.c_uint32),
            ]
        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [("basic_limit_information", BasicLimitInformation), ("io_info", IoCounters),
                        ("process_memory_limit", ctypes.c_size_t), ("job_memory_limit", ctypes.c_size_t),
                        ("peak_process_memory_used", ctypes.c_size_t), ("peak_job_memory_used", ctypes.c_size_t)]
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        is_in_job = kernel32.IsProcessInJob
        is_in_job.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        is_in_job.restype = ctypes.c_int
        current = kernel32.GetCurrentProcess()
        member = ctypes.c_int()
        if not is_in_job(current, None, ctypes.byref(member)):
            return _probe("failed", "kernel32.IsProcessInJob", empty, "Win32 error %d" % ctypes.get_last_error())
        values = dict(empty)
        values["in_job"] = bool(member.value)
        if not member.value:
            return _probe(_STATUS_AVAILABLE, "kernel32.IsProcessInJob", values, "The current process is not assigned to a Job Object.")
        query = kernel32.QueryInformationJobObject
        query.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        query.restype = ctypes.c_int
        info = ExtendedLimitInformation()
        if not query(None, 9, ctypes.byref(info), ctypes.sizeof(info), None):  # JobObjectExtendedLimitInformation
            return _probe("failed", "kernel32.QueryInformationJobObject", values, "Win32 error %d" % ctypes.get_last_error())
        flags = info.basic_limit_information.limit_flags
        values.update({
            "limit_flags": "0x%08X" % flags,
            "active_process_limit": info.basic_limit_information.active_process_limit if flags & 0x00000008 else None,
            "process_memory_limit_bytes": info.process_memory_limit if flags & 0x00000100 else None,
            "job_memory_limit_bytes": info.job_memory_limit if flags & 0x00000200 else None,
            "cpu_time_limit_100ns": {
                "per_process": info.basic_limit_information.per_process_user_time_limit.quad_part if flags & 0x00000002 else None,
                "per_job": info.basic_limit_information.per_job_user_time_limit.quad_part if flags & 0x00000004 else None,
            },
            "affinity_mask": "0x%X" % info.basic_limit_information.affinity if flags & 0x00000010 else None,
        })
        return _probe(_STATUS_AVAILABLE, "kernel32.IsProcessInJob/QueryInformationJobObject", values)
    except (AttributeError, OSError, ValueError) as error:
        return _probe("failed", "kernel32 Job Object API", empty, type(error).__name__)


def _macos_runtime_context() -> dict[str, Any]:
    remote = bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"))
    return {
        "container": _probe(_STATUS_UNSUPPORTED, "macOS", None, "macOS does not expose Linux cgroup container evidence."),
        "wsl": _probe(_STATUS_AVAILABLE, "sys.platform", False),
        "virtual_machine": _probe(_STATUS_UNKNOWN, "portable stdlib", None, "No native hypervisor query was run."),
        "remote_session": _probe(_STATUS_AVAILABLE, "SSH_CONNECTION,SSH_TTY", remote),
        "effective_limits": _probe(_STATUS_UNKNOWN, "portable stdlib", {"cgroup_version": None, "cpu_quota_cores": None, "memory_limit_bytes": None, "allowed_cpu_ids": None}),
    }


def _runtime_context() -> dict[str, Any]:
    if sys.platform.startswith("linux"):
        return _linux_runtime_context()
    if sys.platform == "win32":
        return _windows_runtime_context()
    if sys.platform == "darwin":
        return _macos_runtime_context()
    return {"status": _STATUS_UNSUPPORTED, "source": "sys.platform", "detail": "No runtime-isolation probes are implemented for this platform."}


def _linux_cpu_suitability(cpu: dict[str, Any]) -> dict[str, Any]:
    numa_nodes = []
    for node in sorted(Path("/sys/devices/system/node").glob("node[0-9]*")):
        numa_nodes.append({"node": node.name, "cpu_list": _read_optional(node / "cpulist")})
    policy_roots = sorted(Path("/sys/devices/system/cpu/cpufreq").glob("policy*"))
    governors = sorted({value for root in policy_roots if (value := _read_optional(root / "scaling_governor"))})
    drivers = sorted({value for root in policy_roots if (value := _read_optional(root / "scaling_driver"))})
    flags = cpu.get("instruction_sets") or []
    return {
        "numa": _probe(_STATUS_AVAILABLE, "/sys/devices/system/node", {"node_count": len(numa_nodes), "nodes": numa_nodes}),
        "power_and_performance": _probe(_STATUS_AVAILABLE, "/sys/devices/system/cpu/cpufreq", {"governors": governors, "drivers": drivers, "intel_pstate_status": _read_optional(Path("/sys/devices/system/cpu/intel_pstate/status"))}),
        "virtualization": _probe(_STATUS_AVAILABLE, "/proc/cpuinfo", {"hypervisor_present": "hypervisor" in flags, "hardware_extensions": sorted(set(flags) & {"vmx", "svm"})}),
        "os_enabled_instruction_sets": _probe(_STATUS_AVAILABLE, "/proc/cpuinfo", sorted(flags), "These are flags exposed by the running kernel; this is not a workload test."),
    }


def _generic_cpu_suitability(cpu: dict[str, Any]) -> dict[str, Any]:
    flags = cpu.get("instruction_sets") or []
    return {
        "numa": _probe(_STATUS_UNKNOWN, "portable stdlib", {"node_count": None, "nodes": []}),
        "power_and_performance": _probe(_STATUS_UNKNOWN, "portable stdlib", {"governors": [], "drivers": []}),
        "virtualization": _probe(_STATUS_UNKNOWN, "portable stdlib", {"hypervisor_present": None, "hardware_extensions": []}),
        "os_enabled_instruction_sets": _probe(_STATUS_AVAILABLE if flags else _STATUS_UNKNOWN, "platform CPU probe", sorted(flags), "Processor flags alone do not prove every instruction is usable by an application."),
    }


def _powershell_json(script: str) -> tuple[str, Any, str | None]:
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        return _STATUS_UNAVAILABLE, None, "PowerShell was not found on PATH."
    try:
        completed = subprocess.run((executable, "-NoProfile", "-NonInteractive", "-Command", script), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8, check=False)
    except subprocess.TimeoutExpired:
        return "failed", None, "PowerShell timed out after 8 seconds."
    except OSError as error:
        return "failed", None, str(error)
    if completed.returncode != 0:
        return "failed", None, (completed.stderr or "PowerShell probe failed.").strip()
    try:
        return _STATUS_AVAILABLE, json.loads(completed.stdout), None
    except json.JSONDecodeError as error:
        return "failed", None, "PowerShell returned invalid JSON: %s" % error


def _windows_cpu_suitability(cpu: dict[str, Any]) -> dict[str, Any]:
    status, data, detail = _powershell_json(
        "[ordered]@{processors=@(Get-CimInstance Win32_Processor | Select-Object DeviceID,NumberOfCores,NumberOfLogicalProcessors,VirtualizationFirmwareEnabled,VMMonitorModeExtensions); "
        "computer=Get-CimInstance Win32_ComputerSystem | Select-Object HypervisorPresent,NumberOfLogicalProcessors} | ConvertTo-Json -Depth 3 -Compress"
    )
    processors = data.get("processors") if status == _STATUS_AVAILABLE and isinstance(data, dict) else []
    if isinstance(processors, dict):
        processors = [processors]
    computer = data.get("computer") if status == _STATUS_AVAILABLE and isinstance(data, dict) else {}
    virtualization = {
        "hypervisor_present": computer.get("HypervisorPresent") if isinstance(computer, dict) else None,
        "firmware_enabled": any(item.get("VirtualizationFirmwareEnabled") for item in processors if isinstance(item, dict)),
        "hardware_extensions": ["vm_monitor_mode_extensions"] if any(item.get("VMMonitorModeExtensions") for item in processors if isinstance(item, dict)) else [],
    }
    power = _command_version(("powercfg", "/getactivescheme"))
    flags = cpu.get("instruction_sets") or []
    return {
        "numa": _windows_numa_topology(),
        "power_and_performance": _probe(power["status"], power["source"], {"active_power_scheme": power["value"].get("version") if isinstance(power.get("value"), dict) else None}),
        "virtualization": _probe(status, "PowerShell Win32_Processor,Win32_ComputerSystem", virtualization, detail),
        "os_enabled_instruction_sets": _probe(_STATUS_AVAILABLE if flags else _STATUS_UNKNOWN, "CPUID and IsProcessorFeaturePresent", sorted(flags), "CPUID advertises processor capabilities; application availability can still be constrained by OS policy."),
    }


def _windows_numa_topology() -> dict[str, Any]:
    """Report Windows NUMA nodes and processor groups through kernel32."""
    empty = {"node_count": None, "nodes": []}
    try:
        class GroupAffinity(ctypes.Structure):
            _fields_ = [("mask", ctypes.c_size_t), ("group", ctypes.c_uint16), ("reserved", ctypes.c_uint16 * 3)]
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        highest = ctypes.c_ulong()
        get_highest = kernel32.GetNumaHighestNodeNumber
        get_highest.argtypes = [ctypes.POINTER(ctypes.c_ulong)]
        get_highest.restype = ctypes.c_int
        if not get_highest(ctypes.byref(highest)):
            return _probe("failed", "kernel32.GetNumaHighestNodeNumber", empty, "Win32 error %d" % ctypes.get_last_error())
        get_mask = getattr(kernel32, "GetNumaNodeProcessorMaskEx", None)
        nodes: list[dict[str, Any]] = []
        if get_mask is not None:
            get_mask.argtypes = [ctypes.c_uint16, ctypes.POINTER(GroupAffinity)]
            get_mask.restype = ctypes.c_int
            for node_number in range(highest.value + 1):
                affinity = GroupAffinity()
                if not get_mask(node_number, ctypes.byref(affinity)):
                    nodes.append({"node": node_number, "status": "unavailable", "win32_error": ctypes.get_last_error()})
                    continue
                processors = [bit for bit in range(ctypes.sizeof(ctypes.c_size_t) * 8) if affinity.mask & (1 << bit)]
                nodes.append({"node": node_number, "status": "available", "processor_group": affinity.group, "logical_processor_bits": processors, "mask": "0x%X" % affinity.mask})
            return _probe(_STATUS_AVAILABLE, "kernel32.GetNumaHighestNodeNumber/GetNumaNodeProcessorMaskEx", {"node_count": highest.value + 1, "nodes": nodes}, "Processor bit positions are relative to each Windows processor group.")
        # Legacy fallback covers hosts with up to one processor group.
        get_legacy = kernel32.GetNumaNodeProcessorMask
        get_legacy.argtypes = [ctypes.c_ubyte, ctypes.POINTER(ctypes.c_size_t)]
        get_legacy.restype = ctypes.c_int
        for node_number in range(highest.value + 1):
            mask = ctypes.c_size_t()
            if get_legacy(node_number, ctypes.byref(mask)):
                nodes.append({"node": node_number, "status": "available", "processor_group": 0, "logical_processor_bits": [bit for bit in range(ctypes.sizeof(ctypes.c_size_t) * 8) if mask.value & (1 << bit)], "mask": "0x%X" % mask.value})
            else:
                nodes.append({"node": node_number, "status": "unavailable", "win32_error": ctypes.get_last_error()})
        return _probe(_STATUS_AVAILABLE, "kernel32.GetNumaHighestNodeNumber/GetNumaNodeProcessorMask", {"node_count": highest.value + 1, "nodes": nodes}, "Legacy processor masks do not represent processor groups above 64 logical processors.")
    except (AttributeError, OSError, ValueError) as error:
        return _probe("failed", "kernel32 NUMA API", empty, type(error).__name__)


def _network_details() -> dict[str, Any]:
    if sys.platform.startswith("linux"):
        executable = shutil.which("ip")
        if not executable:
            return _probe(_STATUS_UNAVAILABLE, "PATH", {"interfaces": [], "default_routes": [], "dns_servers": []}, "The optional ip command was not found.")
        try:
            addresses = subprocess.run((executable, "-j", "address"), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, check=False)
            routes = subprocess.run((executable, "-j", "route", "show", "default"), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4, check=False)
            interfaces = json.loads(addresses.stdout) if addresses.returncode == 0 else []
            default_routes = json.loads(routes.stdout) if routes.returncode == 0 else []
            simplified = [
                {"name": item.get("ifname"), "state": item.get("operstate"), "mac_address": item.get("address"), "addresses": [address.get("local") for address in item.get("addr_info", []) if address.get("local")]}
                for item in interfaces if item.get("ifname") != "lo"
            ]
            dns = [line.split(None, 1)[1] for line in (_read_optional(Path("/etc/resolv.conf")) or "").splitlines() if line.startswith("nameserver ")]
            return _probe(_STATUS_AVAILABLE, "ip -j address; ip -j route show default; /etc/resolv.conf", {"interfaces": simplified, "default_routes": default_routes, "dns_servers": dns})
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
            return _probe("failed", "ip", {"interfaces": [], "default_routes": [], "dns_servers": []}, str(error))
    if sys.platform == "win32":
        status, data, detail = _powershell_json(
            "[ordered]@{interfaces=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
            "Select-Object Description,MACAddress,IPAddress,IPSubnet,DefaultIPGateway,DNSServerSearchOrder,InterfaceIndex); "
            "routes=@(Get-CimInstance Win32_IP4RouteTable -Filter 'Destination=\"0.0.0.0\"' | "
            "Select-Object InterfaceIndex,NextHop,Metric1,Destination,Mask)} | ConvertTo-Json -Depth 4 -Compress"
        )
        if status != _STATUS_AVAILABLE:
            return _probe(status, "PowerShell CIM", {"interfaces": [], "default_routes": [], "dns_servers": []}, detail)
        interfaces = data.get("interfaces") or []
        if isinstance(interfaces, dict):
            interfaces = [interfaces]
        routes = data.get("routes") or []
        if isinstance(routes, dict):
            routes = [routes]
        simplified = []
        dns_servers: set[str] = set()
        for item in interfaces:
            dns = item.get("DNSServerSearchOrder") or []
            if isinstance(dns, str):
                dns = [dns]
            dns_servers.update(dns)
            addresses = item.get("IPAddress") or []
            if isinstance(addresses, str):
                addresses = [addresses]
            simplified.append({"name": item.get("Description"), "mac_address": item.get("MACAddress"), "addresses": addresses, "default_gateways": item.get("DefaultIPGateway") or [], "interface_index": item.get("InterfaceIndex")})
        return _probe(_STATUS_AVAILABLE, "PowerShell Win32_NetworkAdapterConfiguration,Win32_IP4RouteTable", {"interfaces": simplified, "default_routes": routes, "dns_servers": sorted(dns_servers)})
    return _probe(_STATUS_UNSUPPORTED, "sys.platform", {"interfaces": [], "default_routes": [], "dns_servers": []}, "Rich network routing probes are currently implemented for Linux only.")


def _display_details() -> dict[str, Any]:
    if sys.platform.startswith("linux"):
        connectors = []
        for connector in sorted(Path("/sys/class/drm").glob("card*-*")):
            status = _read_optional(connector / "status")
            if status:
                modes = (_read_optional(connector / "modes") or "").splitlines()
                connectors.append({"connector": connector.name, "status": status, "modes": modes})
        if connectors:
            return _probe(_STATUS_AVAILABLE, "/sys/class/drm", connectors)
        return _probe(_STATUS_UNAVAILABLE, "/sys/class/drm", [], "No DRM connector information is visible (common on headless systems).")
    if sys.platform == "win32":
        status, data, detail = _powershell_json(
            "@(Get-CimInstance Win32_DesktopMonitor | Select-Object Name,ScreenWidth,ScreenHeight,MonitorType,PNPDeviceID; "
            "Get-CimInstance Win32_VideoController | Select-Object Name,VideoModeDescription,CurrentHorizontalResolution,CurrentVerticalResolution,CurrentRefreshRate) "
            "| ConvertTo-Json -Depth 3 -Compress"
        )
        if status != _STATUS_AVAILABLE:
            return _probe(status, "PowerShell CIM", [], detail)
        records = data if isinstance(data, list) else [data]
        return _probe(_STATUS_AVAILABLE, "PowerShell Win32_DesktopMonitor,Win32_VideoController", records)
    return _probe(_STATUS_UNSUPPORTED, "sys.platform", [], "Detailed connector enumeration is currently implemented for Linux only.")


def collect_developer_context(report_sections: dict[str, Any]) -> dict[str, Any]:
    """Collect opt-in build, runtime, CPU, display, and network diagnostics."""
    result: dict[str, Any] = {
        "status": _STATUS_AVAILABLE,
        "provenance": {"collector": "machine_info.py", "mode": "fixed local read-only probes"},
        "runtime": _runtime_context(),
        "toolchains": _toolchains(),
    }
    if "cpu" in report_sections:
        cpu = report_sections["cpu"].get("cpu", {})
        if sys.platform.startswith("linux"):
            result["cpu_suitability"] = _linux_cpu_suitability(cpu)
        elif sys.platform == "win32":
            result["cpu_suitability"] = _windows_cpu_suitability(cpu)
        else:
            result["cpu_suitability"] = _generic_cpu_suitability(cpu)
    else:
        result["cpu_suitability"] = {"status": "not_collected", "source": "--sections", "detail": "Select the cpu section to collect CPU suitability."}
    result["network"] = _network_details() if "system" in report_sections or "hardware" in report_sections else {"status": "not_collected", "source": "--sections", "detail": "Select system or hardware to collect network details."}
    result["display"] = _display_details() if "hardware" in report_sections else {"status": "not_collected", "source": "--sections", "detail": "Select the hardware section to collect display details."}
    return result



SCHEMA_VERSION = 1
SECTION_NAMES = ("system", "hardware", "cpu")
DEFAULT_INTERVAL_SECONDS = 0.2


def _parse_sections(values: list[str] | None, parser: argparse.ArgumentParser) -> tuple[str, ...]:
    """Normalize repeatable, comma-separated section selections."""
    if not values:
        return SECTION_NAMES

    selected: set[str] = set()
    for value in values:
        for name in value.split(","):
            normalized = name.strip().lower()
            if not normalized:
                parser.error("--sections entries must name system, hardware, or cpu")
            if normalized not in SECTION_NAMES:
                parser.error(f"unknown section {normalized!r}; choose from: {', '.join(SECTION_NAMES)}")
            selected.add(normalized)
    return tuple(name for name in SECTION_NAMES if name in selected)


def collect_machine_info(
    sections: tuple[str, ...] = SECTION_NAMES,
    include_environment: bool = False,
    include_usage: bool = True,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    include_developer_context: bool = False,
) -> dict[str, Any]:
    """Return the facade's stable report while delegating all probes to siblings."""
    report_sections: dict[str, Any] = {}
    if "system" in sections:
        report_sections["system"] = collect_system_info(include_environment)
    if "hardware" in sections:
        report_sections["hardware"] = collect_hardware_info()
    if "cpu" in sections:
        report_sections["cpu"] = collect_cpu_info(interval, include_usage)

    report = {
        "schema_version": SCHEMA_VERSION,
        "platform": {
            "operating_system": platform.system(),
            "operating_system_release": platform.release(),
            "machine": platform.machine(),
        },
        "selected_sections": list(sections),
        "sections": report_sections,
    }
    if include_developer_context:
        report["developer_context"] = collect_developer_context(report_sections)
    return report


def _machine_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Bound the LLM view to decisions, counts, and evidence availability."""
    sections = report.get("sections", {})
    system = sections.get("system", {})
    cpu = sections.get("cpu", {}).get("cpu", {})
    hardware = sections.get("hardware", {}).get("hardware", {})
    context = report.get("developer_context") or {}
    toolchains = context.get("toolchains", [])
    available_tools = [item.get("name") for item in toolchains if item.get("status") == _STATUS_AVAILABLE]
    return {
        "status": _STATUS_AVAILABLE,
        "platform": report.get("platform"),
        "selected_sections": report.get("selected_sections", []),
        "system": {
            "distribution": system.get("operating_system", {}).get("distribution", {}).get("pretty_name"),
            "memory_total_bytes": system.get("resources", {}).get("memory", {}).get("total_bytes"),
        },
        "cpu": {
            "name": cpu.get("name"),
            "physical_cores": cpu.get("physical_cores"),
            "logical_cores": cpu.get("logical_cores"),
            "instruction_set_count": len(cpu.get("instruction_sets", [])),
        },
        "hardware": {
            "graphics_adapter_count": len(hardware.get("graphics", [])),
            "display_count": len(hardware.get("displays", [])),
            "network_adapter_count": len(hardware.get("network", [])),
        },
        "developer_context": {
            "included": bool(context),
            "toolchains_available": available_tools,
            "runtime": context.get("runtime"),
            "cpu_suitability": context.get("cpu_suitability"),
        },
    }


def _human_value(value: Any, unavailable: str = "unavailable") -> str:
    return str(value) if value not in (None, "") else unavailable


def _print_human(report: dict[str, Any]) -> None:
    """Print a deliberately short overview; use --json for full collector data."""
    platform_info = report["platform"]
    print("Machine information")
    print(
        "Platform: %s %s (%s)"
        % (
            _human_value(platform_info.get("operating_system")),
            _human_value(platform_info.get("operating_system_release")),
            _human_value(platform_info.get("machine")),
        )
    )

    sections = report["sections"]
    if "system" in sections:
        system = sections["system"]
        operating_system = system["operating_system"]
        distribution = operating_system.get("distribution", {})
        resources = system.get("resources", {})
        print(
            "System: %s | host: %s | memory total: %s"
            % (
                _human_value(distribution.get("pretty_name") or operating_system.get("family")),
                _human_value(system.get("host", {}).get("hostname")),
                _human_value(resources.get("memory", {}).get("total_bytes")),
            )
        )
    if "hardware" in sections:
        hardware = sections["hardware"].get("hardware", {})
        computer = hardware.get("computer", {})
        model = computer.get("product") or computer.get("model")
        print(
            "Hardware: %s | graphics: %d | storage: %d"
            % (
                _human_value(model),
                len(hardware.get("graphics", [])),
                len(hardware.get("storage", [])),
            )
        )
    if "cpu" in sections:
        cpu = sections["cpu"].get("cpu", {})
        usage = cpu.get("usage") or {}
        usage_value = usage.get("percent")
        usage_text = f"{usage_value}%" if usage_value is not None else "omitted or unavailable"
        print(
            "CPU: %s | cores: %s physical, %s logical | usage: %s"
            % (
                _human_value(cpu.get("name")),
                _human_value(cpu.get("physical_cores")),
                _human_value(cpu.get("logical_cores")),
                usage_text,
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report combined cross-platform system, hardware, and CPU information."
    )
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    parser.add_argument(
        "--sections",
        action="append",
        metavar="LIST",
        help="collect comma-separated sections: system, hardware, cpu; may be repeated (default: all)",
    )
    parser.add_argument(
        "--include-environment",
        action="store_true",
        help="include system environment values; credential-like names remain redacted",
    )
    parser.add_argument(
        "--developer-context",
        action="store_true",
        help="add opt-in runtime limits, fixed toolchain version probes, CPU suitability, and richer network/display evidence",
    )
    parser.add_argument("--no-usage", action="store_true", help="skip the CPU utilization sample")
    parser.add_argument(
        "--interval",
        type=float,
        default=None,
        metavar="SECONDS",
        help=f"CPU usage sample duration; default: {DEFAULT_INTERVAL_SECONDS:g}; must be non-negative",
    )
    add_common_arguments(parser)
    args = parser.parse_args()
    if args.output_schema:
        print(json.dumps(requirements_schema(), indent=2, sort_keys=True, allow_nan=False))
        return 0
    if args.report_schema:
        print(json.dumps(report_schema(), indent=2, sort_keys=True, allow_nan=False))
        return 0
    selected_sections = _parse_sections(args.sections, parser)

    if args.include_environment and "system" not in selected_sections:
        parser.error("--include-environment requires the system section")
    if args.no_usage and "cpu" not in selected_sections:
        parser.error("--no-usage requires the cpu section")
    if args.interval is not None and "cpu" not in selected_sections:
        parser.error("--interval requires the cpu section")
    if args.interval is not None and args.interval < 0:
        parser.error("--interval must be non-negative")
    if args.no_usage and args.interval is not None:
        parser.error("--interval cannot be used with --no-usage")

    interval = DEFAULT_INTERVAL_SECONDS if args.interval is None else args.interval
    report = collect_machine_info(
        sections=selected_sections,
        include_environment=args.include_environment,
        include_usage=not args.no_usage,
        interval=interval,
        include_developer_context=args.developer_context,
    )
    report = finalize_report(report, args, "machine_info", _machine_summary)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str, allow_nan=False))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
