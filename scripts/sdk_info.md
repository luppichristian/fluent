---
description: Find locally installed C/C++ SDK roots, tools, headers, and version evidence.
---

# SDK discovery tool

Finds local C/C++ SDK and library-development evidence across Windows, Linux, and macOS: Android NDK, Apple/Xcode SDKs, Boost, DirectX headers, Emscripten, MSVC, NVIDIA/CUDA, OpenSSL, Qt, SDL, Vulkan, and Windows SDK/Win32 components. It is a read-only inventory intended to answer where roots, headers, and command-line tools are visible to the current process.

## What it reports

- **Emscripten:** `EMSDK`-family variables, an SDK root when derivable, and `emcc`, `em++`, `emcmake`, and `emmake` availability.
- **Vulkan:** `VULKAN_SDK`/`VK_SDK_PATH`, the Vulkan header beneath that root, and `vulkaninfo`, `glslc`, and `glslangValidator` commands.
- **NVIDIA/CUDA:** `CUDA_PATH` versioned variables, CUDA root/header evidence, `nvcc`, and `nvidia-smi` availability. It does not claim that a driver, GPU, or CUDA workload is usable.
- **Windows/Win32:** Windows SDK, UCRT, and MSVC environment roots; Windows Kits registry roots; installed Include version directories; and `rc`, `midl`, and `cl` commands. Non-Windows hosts report this section as `unsupported`.

- **Android NDK:** configured NDK/Android SDK environment roots plus `ndk-build` and `sdkmanager` availability.
- **Qt:** `QTDIR`/CMake package hints, `qmake`, `qtpaths`, and a bounded Qt version query.
- **OpenSSL, SDL, and Boost:** configured roots, their primary headers where available, and common build/configuration commands.
- **MSVC:** configured Visual Studio/VC tools roots plus `cl`, `link`, `lib`, and `vswhere` discovery. It does not claim the current shell is fully initialized.
- **DirectX:** Windows SDK D3D11/D3D12/DXGI/DXC header evidence and the `dxc` command; it does not test a graphics runtime.
- **Apple/Xcode:** on macOS only, `SDKROOT`/`DEVELOPER_DIR`, the macOS SDK from `xcrun`, and Xcode/Clang commands; other hosts explicitly report `unsupported`.
## Run

```sh
python scripts/sdk_info.py --json
python scripts/sdk_info.py --sections vulkan,nvidia --json
python scripts/sdk_info.py --sections windows
```

## Options

| Option | Default | Effect |
| --- | --- | --- |
| `--sections LIST` | all | Comma-separated `android`, `apple`, `boost`, `directx`, `emscripten`, `msvc`, `nvidia`, `openssl`, `qt`, `sdl`, `vulkan`, and/or `windows`. Aliases include `cuda`, `win32`, `dx`, `ndk`, `emsdk`, and `ssl`. |
| `--json` | off | Emit the complete source-labelled report. |
| `-h`, `--help` | n/a | Show usage and exit. |

## Output

Each section has an explicit status: `available` (header/marker evidence), `partial` (tool or package metadata only), `unavailable`, or `unsupported`. Root evidence includes its collection source and whether the path currently exists. Tool entries distinguish a command found on `PATH` from one that is absent. In human-readable mode, each section prints its discovered SDK root paths and found tool executable paths beneath the status; absent paths are omitted. Schema version 3 preserves requested aliases separately from normalized selections and adds platform system/machine data. `--json` emits the complete report.

## Notes

All probes are local and read-only. The tool never installs an SDK, runs a build, scans the entire disk, loads a graphics driver, or establishes that a discovered SDK is configured correctly for a particular project. Reports may include local installation paths and explicitly selected SDK environment-variable values; review them before sharing.
