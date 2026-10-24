---
description: Find locally installed C/C++ SDK roots, tools, headers, and version evidence.
---

# SDK discovery tool

Finds local C/C++ SDK and library-development evidence across Windows, Linux, and macOS: Android NDK, Apple/Xcode SDKs, Boost, DirectX headers, Emscripten, MSVC, NVIDIA/CUDA, OpenSSL, Qt, SDL, Vulkan, and Windows SDK/Win32 components. It is a read-only inventory intended to answer where roots, headers, and command-line tools are visible to the current process.

## What it reports

- **Emscripten:** `EMSDK`-family variables, an SDK root when derivable, and `emcc`, `em++`, `emcmake`, and `emmake` availability.
- **Vulkan:** `VULKAN_SDK`/`VK_SDK_PATH`, the conventional Windows `C:\VulkanSDK\<version>` location, and Unix system roots; Vulkan headers and their declared header revision; plus `vulkaninfo`, `glslc`, and `glslangValidator` commands with version output when available.
- **NVIDIA/CUDA:** `CUDA_PATH` versioned variables, conventional Windows `Program Files\NVIDIA GPU Computing Toolkit\CUDA\<version>` locations, CUDA root/header evidence, `nvcc`, and `nvidia-smi` availability. It does not claim that a driver, GPU, or CUDA workload is usable.
- **Windows/Win32:** Windows SDK, UCRT, and MSVC environment roots; Windows Kits registry roots; installed Include version directories; and `rc`, `midl`, and `cl` commands. Non-Windows hosts report this section as `unsupported`.

- **Android NDK:** configured NDK/Android SDK environment roots plus the standard per-platform Android SDK location, `ndk-build`, and `sdkmanager` availability.
- **Qt:** `QTDIR`/CMake package hints, conventional `C:\Qt\<version>\<kit>` roots on Windows, `qmake`, `qtpaths`, and a bounded Qt version query.
- **OpenSSL, SDL, and Boost:** configured roots, common Windows OpenSSL installation roots, their primary headers where available, and common build/configuration commands.
- **MSVC:** configured Visual Studio/VC tools roots plus `cl`, `link`, `lib`, and `vswhere` discovery. It does not claim the current shell is fully initialized.
- **DirectX:** Windows SDK root, discovered Include version directories, the selected SDK include version, per-header version evidence for D3D11/D3D12/DXGI/DXC, and `dxc` version output when available. It does not test a graphics runtime.
- **Apple/Xcode:** on macOS only, `SDKROOT`/`DEVELOPER_DIR`, the macOS SDK from `xcrun`, and Xcode/Clang commands; other hosts explicitly report `unsupported`.
## Run

```sh
python scripts/sdk_info.py --json
python scripts/sdk_info.py --sections vulkan,nvidia --json
python scripts/sdk_info.py --sections windows
python scripts/sdk_info.py --root D:\\SDKs\\Vulkan --sections vulkan --json
```

## Options

| Option | Default | Effect |
| --- | --- | --- |
| `--sections LIST` | all | Comma-separated `android`, `apple`, `boost`, `directx`, `emscripten`, `msvc`, `nvidia`, `openssl`, `qt`, `sdl`, `vulkan`, and/or `windows`. Aliases include `cuda`, `win32`, `dx`, `ndk`, `emsdk`, and `ssl`. |
| `--root PATH` | none | Check this explicit SDK root directly; repeat for multiple roots. Environment-specific roots take priority. The path is never recursively expanded. |
| `--json` | off | Emit the complete source-labelled report. |
| `-h`, `--help` | n/a | Show usage and exit. |

## Output

Each section has an explicit status: `available` (header/marker evidence), `partial` (tool or package metadata only), `unavailable`, or `unsupported`. Root evidence includes its collection source and whether the path currently exists. Each `--root` is preserved as `requested_roots` in JSON, and a selected root is labelled `argument:--root`. Tool entries distinguish a command found on `PATH` from one that is absent. The Vulkan section preserves the raw `VK_HEADER_VERSION` and `VK_HEADER_VERSION_COMPLETE` definitions as SDK-header evidence, not a runtime or physical-device claim. `glslc` and `glslangValidator` version outputs are captured when available; `vulkaninfo` has no standalone version flag, so its `tool_versions.vulkaninfo` value remains `null` with a source-labelled `not_reported` reason rather than recording its usage text. The DirectX section preserves all discovered Include directories as `include_versions`; `selected_include_version` comes from `WindowsSDKVersion` only when it matches a discovered directory, otherwise it is the newest discovered directory and is labelled accordingly. In human-readable mode, each section prints its discovered SDK root paths and found tool executable paths beneath the status; absent paths are omitted. Schema version 4 preserves requested aliases and roots separately from normalized selections and adds platform system/machine data. `--json` emits the complete report.

## Notes

All probes are local and read-only. The tool never installs an SDK, runs a build, recursively scans arbitrary folders or the entire disk, loads a graphics driver, or establishes that a discovered SDK is configured correctly for a particular project. It examines only a small, documented set of conventional roots, at most two directory levels below those roots. Each supplied `--root` is checked only as given, with no expansion beneath it. Use `--root` for a nonstandard location or set the relevant SDK environment variable. Reports may include local installation paths, explicit `--root` values, and selected SDK environment-variable values; review them before sharing.
