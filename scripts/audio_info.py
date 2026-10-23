#!/usr/bin/env python3
# description: Unified audio capability facade with the OpenAL collector nested intact.
"""Report locally observable audio-runtime capabilities.

This is the public audio entry point. Its built-in OpenAL probe nests its
complete ``openal`` value under ``audio.openal``. The tool intentionally does
not infer hardware features or combine audio APIs into a lossy common shape.
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

SCHEMA_VERSION = 1


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
                "attempted": probe_context,
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


def collect_audio_info(
    probe_context: bool = True, include_openal_info: bool = False
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
    return {
        "schema_version": SCHEMA_VERSION,
        "platform": openal_report["platform"],
        "audio": {"openal": openal_report["openal"]},
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
        description="Report OpenAL audio runtime, device, extension, and context information."
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
    args = parser.parse_args()
    report = collect_audio_info(
        probe_context=not args.no_context,
        include_openal_info=args.include_openal_info,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
