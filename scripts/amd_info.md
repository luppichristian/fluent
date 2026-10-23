---
description: Best-effort AMD GPU, driver, API, media, and ROCm/HIP capability inspector.
---

# AMD information tool

Run the dependency-free, read-only inspector with:

```sh
python scripts/amd_info.py --json
```

It returns a stable top-level JSON object with `schema_version`, `platform`,
`availability`, `driver`, `devices`, `tools`, `probes`, `capabilities`, and
`limitations`. Human-readable output is available by omitting `--json`.
Nested probe fields are best effort: an optional tool, a driver field, or an
API value can be absent or `null` when the platform does not expose it.

The script treats hardware identification and capability evidence separately.
On Windows it uses `Win32_VideoController` CIM data and, when available,
DXDiag XML. On Linux it reads DRM/KFD sysfs data and optional `lspci` output.
It also records whether `rocm-smi`, `amdgpu_top`, `radeontop`, `rocminfo`, HIP
tools, `vainfo`, and `vulkaninfo` can be run. Missing tools, missing drivers,
permissions, a headless host, and virtual machines yield evidence gaps rather
than a script failure.

When `vulkaninfo --json` succeeds, its AMD extension records are retained
under `probes.vulkaninfo.amd_physical_devices`. Only extensions nested under a
physical-device JSON object whose `vendorID` is `0x1002` are considered AMD
evidence; instance extensions and other GPUs are deliberately excluded.

`capabilities.features` reports these AMD-relevant feature families: FidelityFX
Super Resolution, AFMF, HYPR-RX, Anti-Lag, RSR, ray tracing, VCN encode/decode,
ROCm/HIP, and Vulkan/Direct3D evidence. Each record has a `status`, evidence,
scope, and notes. The meanings are deliberately strict:

- `detected` means a local API, runtime, or media-driver probe supplied direct
  evidence for the stated scope.
- `likely_eligible_by_architecture` means a locally reported KFD/ROCm gfx
  architecture is consistent with a feature family. It is never a claim that a
  driver, application, or game enabled the feature.
- `unknown` means no reliable local evidence was found; it does not mean
  unsupported.

FSR versions are game/software integrations, not a generic GPU-driver switch;
the report will therefore never infer FSR support from the GPU name or driver
version. The same caution applies to AMD Software controls such as AFMF,
HYPR-RX, Anti-Lag, and RSR. They need an AMD Software/game/API check to prove
actual availability or activation. Vulkan output can aggregate several GPUs,
and DXDiag DDI or feature-level fields are not a Direct3D extension inventory,
so correlate multi-GPU reports manually.

The report can contain PCI addresses, PnP IDs, driver paths, and installed
driver details. Treat it as machine inventory before sharing it outside the
machine owner’s trust boundary.
