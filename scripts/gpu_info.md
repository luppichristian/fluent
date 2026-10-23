---
description: Read-only GPU inventory plus vendor-feature evidence and graphics/compute API diagnostics.
---

# GPU tool

`gpu_info.py` inventories installed graphics adapters, then optionally probes vendor runtimes and GPU APIs. Use it to answer which GPU/driver is visible, whether a runtime exposes a capability, and where that evidence came from. It does not benchmark hardware or claim an application has enabled a feature.

## What it reports

- Adapter identity, vendor, driver, and PCI/device details when the OS exposes them.
- NVIDIA evidence for DLSS, Reflex, ray tracing, Tensor Cores, NVENC/NVDEC, CUDA, and Vulkan.
- AMD evidence for FSR, AFMF, HYPR-RX, RSR, Anti-Lag, ray tracing, VCN, ROCm/HIP, Direct3D, and Vulkan.
- Direct3D, Vulkan, OpenGL, OpenCL, Metal, and CUDA loader/device/runtime diagnostics.

Each capability carries its source where possible. `unknown`, `unavailable`, or an absent probe is not the same as `false`: it may mean the OS, driver, tool, or runtime could not provide evidence.

## Run

```powershell
python scripts/gpu_info.py
python scripts/gpu_info.py --sections nvidia,cuda,vulkan --json
python scripts/gpu_info.py --full --include-dxdiag --json
```

The default report includes adapter inventory, detected NVIDIA/AMD sections, and Direct3D on Windows or Metal on macOS. It does not run optional API probes or DxDiag.

## Options

| Argument | Behavior |
| --- | --- |
| `--json` | Emit one indented, stable JSON document; otherwise print a summary. |
| `--sections LIST` | Repeatable comma list: `inventory`, `nvidia`, `amd`, `cuda`, `direct3d`, `vulkan`, `opengl`, `opencl`, `metal`. Inventory always runs; vendor sections may be requested even when no matching adapter is found. |
| `--full` | Run all sections; cannot be combined with `--sections`; skips DxDiag by default. |
| `--include-dxdiag` | With `--full`, explicitly enable DxDiag. Conflicts with `--skip-dxdiag`; otherwise has no effect. |
| `--skip-dxdiag` | Suppress DxDiag when Direct3D runs. Overview and `--full` skip it; explicitly requesting `direct3d` enables it unless this flag is set. |
| `-h`, `--help` | Show command help. |

Unknown sections and conflicting options exit with an error.

## JSON output

Top-level keys are `schema_version`, `platform`, `request`, `inventory`, `vendors`, `apis`, and `executed_sections`. Unrequested vendor/API sections are `null`; requested sections contain their payload. A failed optional probe is recorded as `collector_error` while other requested sections continue.

## Notes

All probes are read-only, but some may start local system tools. `--full` can take longer; DxDiag may stall and briefly creates then removes its report. GPU names and PCI IDs identify hardware, not game integration, driver activation, feature enablement, or performance. Reports can contain adapter names, driver versions, PCI IDs, and local paths; review JSON before sharing.
