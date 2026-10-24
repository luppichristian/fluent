---
description: Read-only GPU inventory plus vendor-feature evidence and graphics/compute API diagnostics.
---

# GPU tool

`gpu_info.py` inventories installed graphics adapters, then optionally probes vendor runtimes and GPU APIs. Use it to answer which GPU/driver is visible, whether a runtime exposes a capability, and where that evidence came from. It does not benchmark hardware or claim an application has enabled a feature.

## What it reports

- Adapter identity, vendor, driver, and PCI/device details when the OS exposes them.
- NVIDIA evidence for DLSS, Reflex, ray tracing, Tensor Cores, NVENC/NVDEC, CUDA, and Vulkan. Detected local NGX DLSS components include passive file metadata and, on Windows, version-resource evidence.
- AMD evidence for FSR, AFMF, HYPR-RX, RSR, Anti-Lag, ray tracing, VCN, ROCm/HIP, Direct3D, and Vulkan.
- Direct3D, Vulkan, OpenGL, OpenCL, Metal, and CUDA loader/device/runtime diagnostics. Vulkan includes a loader-only instance API version probe and, when `vulkaninfo` works, instance and physical-device API-version evidence.

On macOS, `--metal-native-probe` attempts a bounded native `MTLCopyAllDevices`
probe through the locally installed Swift toolchain. It reports native device
identity, supported Metal GPU families, and low-power/headless/removable/unified
memory properties when available. Metal does not expose one independently
queryable runtime API-version number: the supported GPU-family list is the
capability evidence, while Xcode/Metal compiler versions describe tooling only.

Each capability carries its source where possible. `unknown`, `unavailable`, or an absent probe is not the same as `false`: it may mean the OS, driver, tool, or runtime could not provide evidence.

## Run

```powershell
python scripts/gpu_info.py
python scripts/gpu_info.py --sections nvidia,cuda,vulkan --json
python scripts/gpu_info.py --full --include-dxdiag --json
python scripts/gpu_info.py --full --profile llm --redact default --json
python scripts/gpu_info.py --sections direct3d --smoke-test d3d11,d3d12 --json
python scripts/gpu_info.py --sections direct3d --per-adapter-probe d3d11,d3d12 --skip-dxdiag --json
```

The default report includes adapter inventory, detected NVIDIA/AMD sections, and Direct3D on Windows or Metal on macOS. It does not run optional API probes or DxDiag. A selected Vulkan section safely calls `vkEnumerateInstanceVersion` when a loader is discoverable; it loads no ICD, creates no Vulkan instance, and does not establish physical-device support.

## Options

| Argument | Behavior |
| --- | --- |
| `--json` | Emit one indented, stable JSON document; otherwise print a summary. |
| `--sections LIST` | Repeatable comma list: `inventory`, `nvidia`, `amd`, `cuda`, `direct3d`, `vulkan`, `opengl`, `opencl`, `metal`. Inventory always runs; vendor sections may be requested even when no matching adapter is found. |
| `--full` | Run all sections; cannot be combined with `--sections`; skips DxDiag by default. |
| `--include-dxdiag` | With `--full`, explicitly enable DxDiag. Conflicts with `--skip-dxdiag`; otherwise has no effect. |
| `--skip-dxdiag` | Suppress DxDiag when Direct3D runs. Overview and `--full` skip it; explicitly requesting `direct3d` enables it unless this flag is set. |
| `--smoke-test LIST` | Opt-in active initialization probe. `d3d11` creates a D3D11 device for Windows' default hardware adapter and records its selected feature level. `d3d12` creates the default D3D12 device and queries documented base Options tiers. `all` runs both. Each immediately releases its device; neither renders, benchmarks, or proves an application path. |
| `--per-adapter-probe LIST` | Opt-in DXGI enumeration and active probe of every non-software DXGI adapter. Accepts `d3d11`, `d3d12`, or `all`; each created device is released immediately. Results retain DXGI identity and do not equate its adapter order with CIM, Vulkan, CUDA, or an application's adapter selection. |
| `--metal-native-probe` | On macOS, opt in to native `MTLCopyAllDevices` capability discovery through a temporary Swift program. Reports each available device's supported Metal GPU families and basic topology; it creates no workload. |
| `--profile full\|llm\|summary` | `full` is the existing raw-evidence view. `llm` and `summary` emit a bounded cross-API capability profile without large Vulkan/DxDiag/tool payloads. Combine `--full --profile llm` to collect all APIs but transport only the compact view. |
| `--redact none\|default\|strict` | Replace local identifiers in emitted or saved reports. Use `default` before sharing; `none` remains the compatibility default. |
| `--requirements PATH` | Evaluate a JSON requirements manifest against the full report before it is summarized. |
| `--compare PATH` / `--save PATH` | Add a bounded comparison to an earlier JSON snapshot or save the final redacted full report. |
| `--envelope` | Wrap full evidence in the common `tool`/`status`/`metadata` envelope while preserving the default raw contract when omitted. |
| `--output-schema` | Print the requirements-manifest contract and exit without collecting. |
| `--report-schema` | Print the Draft 2020-12 JSON Schema for legacy or enveloped GPU reports. |
| `-h`, `--help` | Show command help. |

Unknown sections and conflicting options exit with an error.

## JSON output

Full-report top-level keys are `schema_version`, `platform`, `request`, `inventory`, `vendors`, `apis`, `executed_sections`, and `smoke_tests` (plus common metadata/output controls). Unrequested vendor/API sections are `null`; requested sections contain their payload. A failed optional probe is recorded as `collector_error` while other requested sections continue.

The compact profile has normalized API status/provenance, a conservative canonical-adapter matrix, and Windows active-display diagnostics from DisplayConfig: active adapter paths, refresh rate, HDR/advanced-color support and enabled state, and hybrid-topology evidence. NVIDIA telemetry is included when `nvidia-smi` provides it. On Windows it also records the current user's variable-refresh-rate preference if the documented DirectX user-preferences registry value is present; that is not proof of monitor support or per-application activation. It matches identities by UUID, PCI, or an exact OS PNP identity where exposed; a name-only association is explicitly labelled lower confidence. It does **not** silently equate CUDA, Vulkan, OS, or Direct3D ordinals.

## Notes

All inventory probes are read-only, but `--smoke-test d3d11` and `d3d12` are explicit exceptions: they initialize then release a default Direct3D device and report `passed`, `unavailable`, or `not_applicable`; no result is inferred from an adapter name. `--per-adapter-probe` does the same against explicitly enumerated non-software DXGI adapters. `--metal-native-probe` may create temporary `MTLDevice` references to enumerate native capabilities; it creates no queue, surface, command list, pipeline, renderer, or workload. NVIDIA NGX inspection reads file metadata and (on Windows) version resources without loading NGX. An NGX component version does not prove DLSS 5, GPU eligibility, driver support, or support in a particular application; `dlss_5` is intentionally `unknown` unless a future safe, documented NGX query can establish it. `--full` can take longer; DxDiag may stall and briefly creates then removes its report. GPU names and PCI IDs identify hardware, not game integration, driver activation, feature enablement, or performance. Reports can contain adapter names, driver versions, PCI IDs, and local paths; review JSON before sharing.
