#!/usr/bin/env python3
# description: Find locally installed C/C++ SDK roots, tools, headers, and version evidence.
"""Read-only discovery for common native and graphics SDK installations."""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Any

SECTIONS = ("android", "apple", "boost", "directx", "emscripten", "msvc", "nvidia", "openssl", "qt", "sdl", "vulkan", "windows")

ALIASES = {"android-ndk": "android", "cuda": "nvidia", "dx": "directx", "emsdk": "emscripten", "ndk": "android", "ssl": "openssl", "win32": "windows", "windows-sdk": "windows", "winsdk": "windows"}


def evidence(value: str | None, source: str) -> dict[str, Any]:
    """Return source-labelled evidence without treating a path as usable."""
    return {"value": value, "source": source, "exists": bool(value and Path(value).exists())}


def tool(name: str) -> dict[str, Any]:
    path = shutil.which(name)
    return {"path": path, "status": "available" if path else "unavailable"}


def version(command: list[str], timeout: float = 3.0) -> str | None:
    try:
        with tempfile.TemporaryFile(mode="w+b") as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout, shell=False)
            output.seek(0)
            text = output.read(4096).decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return text[:1000] or None


def paths_from_environment(names: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    return {name: evidence(os.environ.get(name), f"environment:{name}") for name in names if os.environ.get(name)}


def header(root: str | None, *parts: str) -> bool:
    return bool(root and Path(root).joinpath(*parts).is_file())


def first_existing(candidates: tuple[tuple[str, str | None], ...]) -> tuple[str | None, str]:
    """Choose the first readable conventional root; never scan arbitrary disks."""
    for source, value in candidates:
        if value:
            try:
                if Path(value).is_dir():
                    return value, source
            except OSError:
                pass
    return None, "not-found"


def first_matching(candidates: tuple[tuple[str, str | None], ...], matcher: Any) -> tuple[str | None, str]:
    """Choose the first root that contains a section-specific marker."""
    for source, value in candidates:
        if value:
            try:
                if matcher(str(value)):
                    return str(value), source
            except OSError:
                pass
    return None, "not-found"


def child_directories(path: str | Path) -> tuple[str, ...]:
    """Return immediate child directories from an explicit conventional root."""
    try:
        return tuple(str(item) for item in Path(path).iterdir() if item.is_dir())
    except OSError:
        return ()


def conventional_roots(label: str, bases: tuple[str | None, ...], depth: int = 0) -> tuple[tuple[str, str], ...]:
    """Expand a small, named conventional SDK location without disk crawling."""
    paths = tuple(str(Path(base)) for base in bases if base)
    for _ in range(depth):
        paths = tuple(child for path in paths for child in child_directories(path))
    return tuple((f"conventional:{label}:{path}", path) for path in paths)


def argument_roots(roots: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Label explicit user roots without expanding or searching beneath them."""
    return tuple(("argument:--root", root) for root in roots)


def windows_program_files(*parts: str) -> tuple[str, ...]:
    """Build deduplicated conventional Program Files paths on Windows only."""
    if platform.system() != "Windows":
        return ()
    values = (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"))
    return tuple(dict.fromkeys(str(Path(value).joinpath(*parts)) for value in values if value))


def package_version(names: tuple[str, ...]) -> dict[str, Any]:
    """Ask pkg-config only for fixed package names, with bounded local output."""
    executable = shutil.which("pkg-config") or shutil.which("pkgconf")
    if not executable:
        return {"status": "unavailable", "package": None, "version": None}
    for name in names:
        value = version([executable, "--modversion", name])
        if value:
            return {"status": "available", "package": name, "version": value}

    return {"status": "unavailable", "package": None, "version": None}


def development_status(artifacts: dict[str, bool], tools: dict[str, dict[str, Any]], package: dict[str, Any] | None = None) -> str:
    """Require a header/marker for available; commands or metadata alone are partial."""
    if any(artifacts.values()):
        return "available"
    if (package and package["status"] == "available") or any(item["status"] == "available" for item in tools.values()):
        return "partial"
    return "unavailable"


def android(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    ndk = tool("ndk-build")
    sdk_home = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    standard_sdk_roots = (
        str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk") if platform.system() == "Windows" and os.environ.get("LOCALAPPDATA") else None,
        str(Path.home() / "Library" / "Android" / "sdk") if platform.system() == "Darwin" else None,
        str(Path.home() / "Android" / "Sdk") if platform.system() == "Linux" else None,
    )
    candidates = tuple((f"environment:{name}", os.environ.get(name)) for name in ("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME", "NDK_HOME"))
    candidates += argument_roots(roots)
    candidates += (("android-sdk:ndk", str(Path(sdk_home) / "ndk")) if sdk_home else ())
    candidates += conventional_roots("android-sdk-ndk", tuple(str(Path(path) / "ndk") for path in standard_sdk_roots if path), depth=1)
    root, source = first_matching(candidates, lambda path: header(path, "source.properties") or header(path, "build", "cmake", "android.toolchain.cmake"))
    markers = {"source.properties": header(root, "source.properties"), "android.toolchain.cmake": header(root, "build", "cmake", "android.toolchain.cmake")}
    tools = {"ndk-build": ndk, "sdkmanager": tool("sdkmanager")}
    return {"status": development_status(markers, tools), "environment": paths_from_environment(("ANDROID_NDK_ROOT", "ANDROID_NDK_HOME", "NDK_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT")), "root": evidence(root, source), "markers": markers, "tools": tools}

def qt(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    qmake = tool("qmake")
    configured_root = next((os.environ.get(name) for name in ("QTDIR", "Qt6_DIR", "Qt5_DIR") if os.environ.get(name)), None)
    standard_roots = conventional_roots("qt", (r"C:\Qt",), depth=2) if platform.system() == "Windows" else ()
    root, source = first_matching((("environment:QTDIR/Qt*_DIR", configured_root),) + argument_roots(roots) + standard_roots, lambda path: header(path, "include", "QtCore", "qglobal.h") or header(path, "QtCore", "qglobal.h"))
    tools = {"qmake": qmake, "qtpaths": tool("qtpaths"), "cmake": tool("cmake")}
    headers = {"QtCore/qglobal.h": header(root, "include", "QtCore", "qglobal.h") or header(root, "QtCore", "qglobal.h")}
    package = package_version(("Qt6Core", "Qt5Core"))
    return {"status": development_status(headers, {"qmake": qmake, "qtpaths": tools["qtpaths"]}, package), "environment": paths_from_environment(("QTDIR", "Qt6_DIR", "Qt5_DIR")), "root": evidence(root, source), "headers": headers, "package": package, "tools": tools, "qmake_version": version([str(qmake["path"]), "-query", "QT_VERSION"]) if qmake["path"] else None}

def openssl(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    executable = tool("openssl")
    configured_root = next((os.environ.get(name) for name in ("OPENSSL_ROOT_DIR", "OPENSSL_ROOT") if os.environ.get(name)), None)
    standard_roots = tuple((f"conventional:openssl:{path}", path) for path in windows_program_files("OpenSSL-Win64")) + tuple((f"conventional:openssl:{path}", path) for path in windows_program_files("OpenSSL-Win32"))
    root, source = first_matching((("environment:OPENSSL_ROOT*", configured_root),) + argument_roots(roots) + standard_roots, lambda path: header(path, "include", "openssl", "ssl.h") or header(path, "Include", "openssl", "ssl.h"))
    headers = {"openssl/ssl.h": header(root, "include", "openssl", "ssl.h") or header(root, "Include", "openssl", "ssl.h")}
    package = package_version(("openssl", "libssl")); return {"status": development_status(headers, {"openssl": executable}, package), "environment": paths_from_environment(("OPENSSL_ROOT_DIR", "OPENSSL_ROOT")), "root": evidence(root, source), "headers": headers, "package": package, "tools": {"openssl": executable}, "version": version([str(executable["path"]), "version"]) if executable["path"] else None}


def sdl(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    configured_root = next((os.environ.get(name) for name in ("SDL3DIR", "SDL2DIR", "SDL_DIR") if os.environ.get(name)), None)
    root, source = first_matching((("environment:SDL*_DIR", configured_root),) + argument_roots(roots), lambda path: header(path, "include", "SDL.h") or header(path, "include", "SDL2", "SDL.h") or header(path, "include", "SDL3", "SDL.h"))
    tools = {"sdl2-config": tool("sdl2-config"), "sdl3-config": tool("sdl3-config"), "pkg-config": tool("pkg-config")}
    headers = {"SDL.h": header(root, "include", "SDL.h") or header(root, "include", "SDL2", "SDL.h") or header(root, "include", "SDL3", "SDL.h")}
    package = package_version(("sdl3", "sdl2")); return {"status": development_status(headers, tools, package), "environment": paths_from_environment(("SDL3DIR", "SDL2DIR", "SDL_DIR")), "root": evidence(root, source), "headers": headers, "package": package, "tools": tools}


def boost(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    configured_root = os.environ.get("BOOST_ROOT") or os.environ.get("Boost_ROOT")
    root, source = first_matching((("environment:BOOST_ROOT/Boost_ROOT", configured_root),) + argument_roots(roots), lambda path: header(path, "boost", "version.hpp") or header(path, "include", "boost", "version.hpp"))
    tools = {"b2": tool("b2"), "bjam": tool("bjam")}; headers = {"boost/version.hpp": header(root, "boost", "version.hpp") or header(root, "include", "boost", "version.hpp")}; package = package_version(("boost",))
    return {"status": development_status(headers, tools, package), "environment": paths_from_environment(("BOOST_ROOT", "Boost_ROOT")), "root": evidence(root, source), "headers": headers, "package": package, "tools": tools}


def msvc(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    configured_root = os.environ.get("VCToolsInstallDir") or os.environ.get("VCINSTALLDIR")
    root, source = first_matching((("environment:VCToolsInstallDir/VCINSTALLDIR", configured_root),) + argument_roots(roots), lambda path: header(path, "include", "vcruntime.h"))
    tools = {name: tool(name) for name in ("cl", "link", "lib", "vswhere")}
    headers = {"vcruntime.h": header(root, "include", "vcruntime.h")}
    status = "unsupported" if platform.system() != "Windows" else development_status(headers, {"cl": tools["cl"]})
    return {"status": status, "environment": paths_from_environment(("VSINSTALLDIR", "VCINSTALLDIR", "VCToolsInstallDir", "VCToolsVersion", "VisualStudioVersion")), "root": evidence(root, source), "headers": headers, "tools": tools}


def _windows_sdk_version_key(value: str) -> tuple[int, ...]:
    """Sort Windows SDK include-directory names without assuming they parse."""
    numbers = re.findall(r"\d+", value)
    return tuple(int(number) for number in numbers) if numbers else (-1,)


def directx(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    if platform.system() != "Windows":
        return {"status": "unsupported", "root": evidence(None, "windows-sdk"), "include_versions": [], "selected_include_version": None, "header_versions": {}, "headers": {}, "tools": {}}
    configured_root = os.environ.get("WindowsSdkDir") or registry_values().get("KitsRoot10")
    kit_root, root_source = first_matching((("environment:WindowsSdkDir/registry:KitsRoot10", configured_root),) + argument_roots(roots), lambda path: (Path(path) / "Include").is_dir())
    include_root = Path(kit_root) / "Include" if kit_root else None
    try:
        version_paths = [path for path in include_root.iterdir() if path.is_dir()] if include_root and include_root.is_dir() else []
    except OSError:
        version_paths = []
    include_versions = sorted((path.name for path in version_paths), key=_windows_sdk_version_key)
    requested_version = (os.environ.get("WindowsSDKVersion") or "").strip().rstrip("\\/")
    selected_include_version = requested_version if requested_version in include_versions else (include_versions[-1] if include_versions else None)
    names = ("d3d11.h", "d3d12.h", "dxgi1_6.h", "dxcapi.h")
    header_versions = {name: [path.name for path in version_paths if (path / "um" / name).is_file()] for name in names}
    headers = {name: bool(values) for name, values in header_versions.items()}
    tools = {"dxc": tool("dxc")}
    return {
        "status": development_status(headers, tools),
        "root": evidence(kit_root, root_source),
        "include_versions": include_versions,
        "selected_include_version": selected_include_version,
        "selected_include_version_source": "environment:WindowsSDKVersion" if requested_version in include_versions else ("latest_discovered_include_directory" if selected_include_version else "unavailable"),
        "header_versions": header_versions,
        "headers": headers,
        "tools": tools,
        "dxc_version": version([str(tools["dxc"]["path"]), "--version"]) if tools["dxc"]["path"] else None,
    }

def apple(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    if platform.system() != "Darwin":
        return {"status": "unsupported", "environment": {}, "root": evidence(None, "xcrun:macosx"), "tools": {}}
    xcrun = tool("xcrun")
    sdk = os.environ.get("SDKROOT")
    if not sdk and xcrun["path"]:
        candidate = version([str(xcrun["path"]), "--show-sdk-path", "--sdk", "macosx"])
        sdk = candidate if candidate and Path(candidate).is_dir() else None
    root, source = first_matching((("environment:SDKROOT", sdk), ("environment:DEVELOPER_DIR", os.environ.get("DEVELOPER_DIR"))) + argument_roots(roots), lambda path: header(path, "System", "Library", "Frameworks", "Foundation.framework", "Headers", "Foundation.h"))
    if not root and sdk:
        root, source = sdk, "environment:SDKROOT"
    return {"status": "available" if root or xcrun["path"] else "unavailable", "environment": paths_from_environment(("SDKROOT", "DEVELOPER_DIR")), "root": evidence(root or os.environ.get("DEVELOPER_DIR"), source if root else ("environment:DEVELOPER_DIR" if os.environ.get("DEVELOPER_DIR") else "xcrun:macosx")), "headers": {"Foundation/Foundation.h": header(root, "System", "Library", "Frameworks", "Foundation.framework", "Headers", "Foundation.h")}, "tools": {"xcrun": xcrun, "xcodebuild": tool("xcodebuild"), "clang": tool("clang")}}


def emscripten(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    emcc = tool("emcc")
    configured_root = os.environ.get("EMSDK")
    root, source = first_matching((("environment:EMSDK", configured_root),) + argument_roots(roots), lambda path: (Path(path) / "upstream" / "emscripten").is_dir())
    if not root and emcc["path"]:
        candidate = Path(str(emcc["path"])).resolve().parent.parent
        root = str(candidate) if (candidate / "upstream" / "emscripten").is_dir() else None
        source = "derived:emcc" if root else "not-found"
    tools = {"emcc": emcc, "em++": tool("em++"), "emcmake": tool("emcmake"), "emmake": tool("emmake")}
    markers = {"upstream/emscripten": bool(root and (Path(root) / "upstream" / "emscripten").is_dir())}
    return {"status": development_status(markers, tools), "environment": paths_from_environment(("EMSDK", "EM_CONFIG", "EMSDK_NODE")), "root": evidence(root, source), "markers": markers, "tools": tools, "version": version([str(emcc["path"]), "--version"]) if emcc["path"] else None}

def vulkan(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    windows_roots = conventional_roots("vulkan", (r"C:\VulkanSDK",), depth=1) if platform.system() == "Windows" else ()
    candidates = [("environment:VULKAN_SDK", os.environ.get("VULKAN_SDK")), ("environment:VK_SDK_PATH", os.environ.get("VK_SDK_PATH")), *argument_roots(roots), *windows_roots, ("system:/usr", "/usr"), ("system:/usr/local", "/usr/local"), ("system:/opt/vulkan", "/opt/vulkan")]
    root, source = first_matching(tuple(candidates), lambda path: header(path, "Include", "vulkan", "vulkan.h") or header(path, "include", "vulkan", "vulkan.h"))
    headers = {"vulkan.h": header(root, "Include", "vulkan", "vulkan.h") or header(root, "include", "vulkan", "vulkan.h")}
    tools = {"vulkaninfo": tool("vulkaninfo"), "glslc": tool("glslc"), "glslangValidator": tool("glslangValidator")}
    package = package_version(("vulkan",))
    header_path = None
    if root:
        for parts in (("Include", "vulkan", "vulkan_core.h"), ("include", "vulkan", "vulkan_core.h")):
            candidate = Path(root).joinpath(*parts)
            if candidate.is_file():
                header_path = candidate
                break
    header_version: dict[str, Any] = {"path": str(header_path) if header_path else None, "VK_HEADER_VERSION": None, "VK_HEADER_VERSION_COMPLETE": None}
    if header_path:
        try:
            text = header_path.read_text(encoding="utf-8", errors="replace")[:512000]
            for name in ("VK_HEADER_VERSION", "VK_HEADER_VERSION_COMPLETE"):
                match = re.search(r"^\s*#\s*define\s+%s\s+(.+?)\s*$" % re.escape(name), text, re.MULTILINE)
                header_version[name] = match.group(1).strip() if match else None
        except OSError:
            pass
    # `vulkaninfo` deliberately exposes report modes, not a documented
    # standalone version option.  Do not mistake its usage banner for a version.
    tool_versions = {
        "vulkaninfo": None,
        "glslc": version([str(tools["glslc"]["path"]), "--version"]) if tools["glslc"]["path"] else None,
        "glslangValidator": version([str(tools["glslangValidator"]["path"]), "--version"]) if tools["glslangValidator"]["path"] else None,
    }
    tool_version_probes = {
        "vulkaninfo": {"status": "not_reported", "command": None, "reason": "vulkaninfo has no documented standalone version option"} if tools["vulkaninfo"]["path"] else {"status": "unavailable", "command": None, "reason": "command was not found"},
        "glslc": {"status": "available" if tool_versions["glslc"] else "unavailable", "command": ["glslc", "--version"] if tools["glslc"]["path"] else None},
        "glslangValidator": {"status": "available" if tool_versions["glslangValidator"] else "unavailable", "command": ["glslangValidator", "--version"] if tools["glslangValidator"]["path"] else None},
    }
    return {"status": development_status(headers, tools, package), "environment": paths_from_environment(("VULKAN_SDK", "VK_SDK_PATH", "VK_LAYER_PATH", "VK_ICD_FILENAMES")), "root": evidence(root, source), "headers": headers, "header_version": header_version, "package": package, "tools": tools, "tool_versions": tool_versions, "tool_version_probes": tool_version_probes}

def nvidia(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    nvcc = tool("nvcc")
    environment = paths_from_environment(tuple(name for name in os.environ if re.fullmatch(r"CUDA_(?:PATH|HOME|ROOT)(?:_V\d+_\d+)?", name, re.IGNORECASE)))
    windows_roots = conventional_roots("cuda", windows_program_files("NVIDIA GPU Computing Toolkit", "CUDA"), depth=1)
    candidates = [(f"environment:{name}", os.environ.get(name)) for name in os.environ if re.fullmatch(r"CUDA_(?:PATH|HOME|ROOT)(?:_V\d+_\d+)?", name, re.IGNORECASE)] + [*argument_roots(roots), *windows_roots, ("system:/usr/local/cuda", "/usr/local/cuda"), ("system:/opt/cuda", "/opt/cuda")]
    primary, source = first_matching(tuple(candidates), lambda path: header(path, "include", "cuda.h"))
    headers = {"cuda.h": header(primary, "include", "cuda.h")}
    tools = {"nvcc": nvcc, "nvidia-smi": tool("nvidia-smi")}
    return {"status": development_status(headers, {"nvcc": nvcc}), "environment": environment, "cuda_root": evidence(primary, source), "headers": headers, "tools": tools, "nvcc_version": version([str(nvcc["path"]), "--version"]) if nvcc["path"] else None}

def registry_values() -> dict[str, str]:
    if platform.system() != "Windows":
        return {}
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Kits\Installed Roots")
        return {name: str(winreg.QueryValueEx(key, name)[0]) for name in ("KitsRoot10", "KitsRoot81") if _registry_has(key, name)}
    except OSError:
        return {}


def _registry_has(key: Any, name: str) -> bool:
    try:
        import winreg
        winreg.QueryValueEx(key, name)
        return True
    except OSError:
        return False


def windows(roots: tuple[str, ...] = ()) -> dict[str, Any]:
    registry = registry_values()
    environment = paths_from_environment(("WindowsSdkDir", "WindowsSDKVersion", "UniversalCRTSdkDir", "VCToolsInstallDir"))
    environment.update({name: evidence(value, f"registry:Windows Kits Installed Roots/{name}") for name, value in registry.items()})
    configured_root = os.environ.get("WindowsSdkDir") or registry.get("KitsRoot10")
    kit_root, root_source = first_matching((("environment:WindowsSdkDir/registry:KitsRoot10", configured_root),) + argument_roots(roots), lambda path: (Path(path) / "Include").is_dir())
    try:
        includes = list((Path(kit_root) / "Include").glob("*")) if kit_root and (Path(kit_root) / "Include").is_dir() else []
    except OSError:
        includes = []
    return {
        "status": "available" if kit_root else ("unsupported" if platform.system() != "Windows" else "unavailable"),
        "roots": environment,
        "windows_sdk_root": evidence(kit_root, root_source),
        "include_versions": sorted(path.name for path in includes if path.is_dir()),
        "tools": {"rc": tool("rc"), "midl": tool("midl"), "cl": tool("cl")},
    }


def human_section_lines(name: str, item: dict[str, Any]) -> list[str]:
    """Render status plus discovered SDK roots and executable paths."""
    lines = [f"{name}: {item.get('status', 'unknown')}"]
    shown_paths: set[str] = set()

    def add_evidence(label: str, value: Any) -> None:
        if not isinstance(value, dict):
            return
        path = value.get("value")
        if not path or str(path) in shown_paths:
            return
        shown_paths.add(str(path))
        source = value.get("source")
        suffix = f" ({source})" if source else ""
        lines.append(f"  {label}: {path}{suffix}")

    for key in ("root", "cuda_root", "windows_sdk_root"):
        add_evidence(key.replace("_", " "), item.get(key))
    roots = item.get("roots")
    if isinstance(roots, dict):
        for key, value in roots.items():
            add_evidence(str(key), value)

    tools = item.get("tools")
    if isinstance(tools, dict):
        found = [f"{key}={value['path']}" for key, value in tools.items() if isinstance(value, dict) and value.get("path")]
        if found:
            lines.append("  tools: " + "; ".join(found))
    if name == "directx":
        selected = item.get("selected_include_version")
        versions = item.get("include_versions")
        if selected:
            lines.append("  selected Windows SDK include version: %s" % selected)
        if isinstance(versions, list) and versions:
            lines.append("  discovered Windows SDK include versions: " + ", ".join(str(value) for value in versions))
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Find local C/C++ SDK and library-development evidence without installing or invoking builds.")
    parser.add_argument("--sections", default=",".join(SECTIONS), help="comma-separated: android,apple,boost,directx,emscripten,msvc,nvidia,openssl,qt,sdl,vulkan,windows; aliases: cuda,win32,dx,ndk,emsdk,ssl")
    parser.add_argument("--root", action="append", default=[], metavar="PATH", help="explicit SDK root to check directly; repeat for multiple roots")
    parser.add_argument("--json", action="store_true", help="emit the full machine-readable report")
    args = parser.parse_args()
    requested = tuple(part.strip().casefold() for part in args.sections.split(",") if part.strip())
    selected = tuple(dict.fromkeys(ALIASES.get(name, name) for name in requested))
    invalid = sorted(set(selected).difference(SECTIONS))
    if invalid or not selected:
        parser.error("--sections must contain one or more of: " + ", ".join(SECTIONS))
    collectors = {"android": android, "apple": apple, "boost": boost, "directx": directx, "emscripten": emscripten, "msvc": msvc, "nvidia": nvidia, "openssl": openssl, "qt": qt, "sdl": sdl, "vulkan": vulkan, "windows": windows}
    roots = tuple(args.root)
    report = {"tool": "sdk_info", "schema_version": 4, "platform": {"system": platform.system(), "machine": platform.machine()}, "requested_sections": list(requested), "selected_sections": list(selected), "section_aliases": {name: ALIASES[name] for name in requested if name in ALIASES}, "requested_roots": list(roots), "sections": {name: collectors[name](roots) for name in selected}}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for name, item in report["sections"].items():
            print("\n".join(human_section_lines(name, item)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
