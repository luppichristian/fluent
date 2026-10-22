#!/usr/bin/env python3
# description: Cross-platform operating system, runtime, and current-user inspector.
"""Report system and current-user information without third-party packages.

The report is deliberately local and read-only.  It does not print environment
variable values unless ``--include-environment`` is supplied; values whose
names look like credentials are redacted even with that explicit opt-in.
Operating-system-specific probes are best effort, so a field can be ``null``
when an OS, policy, or restricted runtime does not expose it.
"""

from __future__ import annotations

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


def _format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "unavailable"
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"


def _format_bytes(value: int | None) -> str:
    if value is None:
        return "unavailable"
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:g} {unit}"
        amount /= 1024
    return "unavailable"


def _print_human(report: dict[str, Any]) -> None:
    operating_system = report["operating_system"]
    host = report["host"]
    user = report["user"]
    resources = report["resources"]
    process = report["process"]
    distribution = operating_system["distribution"]
    print(f"System: {distribution.get('pretty_name') or operating_system.get('family') or 'Unknown'}")
    print(f"Kernel: {operating_system.get('kernel_release') or 'unknown'} ({operating_system.get('machine') or 'unknown'})")
    print(f"Host: {host.get('hostname') or 'unknown'} | boot: {host.get('boot_time_utc') or 'unavailable'} | uptime: {_format_duration(host.get('uptime_seconds'))}")
    print(f"User: {user.get('qualified_name') or user.get('username') or 'unknown'} | administrator: {user.get('is_administrator')}")
    print(f"Locale: {report['locale'].get('language') or 'unknown'} | timezone: {report['locale'].get('timezone') or 'unknown'}")
    memory = resources["memory"]
    print(f"Memory: {_format_bytes(memory.get('used_bytes'))} used / {_format_bytes(memory.get('total_bytes'))} total")
    print(f"Runtime: Python {process['python'].get('version') or 'unknown'} (PID {process.get('pid')}, {process.get('runtime_seconds')}s)")
    environment = report["environment"]
    if not environment["included"]:
        print("Environment: omitted (pass --include-environment to opt in; likely secrets remain redacted)")
    else:
        print(f"Environment ({environment['count']} variables; {environment['redacted_count']} redacted):")
        for name, value in environment["variables"].items():
            print(f"  {name}={value}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Report cross-platform system, runtime, and current-user information.")
    parser.add_argument("--json", action="store_true", help="emit one stable JSON object for programs and LLM tool calls")
    parser.add_argument("--include-environment", action="store_true", help="include environment values; credential-like names are still redacted")
    args = parser.parse_args()
    report = collect_system_info(args.include_environment)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
