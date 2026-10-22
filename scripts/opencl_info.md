---
description: Cross-platform OpenCL platform, device, ICD, and capability inspector.
---

# OpenCL information tool

Run [`opencl_info.py`](opencl_info.py) to inspect the installed OpenCL loader,
ICD configuration, platforms, and devices without installing `pyopencl` or an
OpenCL SDK.

```sh
python scripts/opencl_info.py --json
```

The stable top-level JSON object is `schema_version`, `platform`,
`availability`, `probes`, `installations`, and `platforms`. It distinguishes a
missing loader, a loader with no registered platform, and an available runtime.
On Linux it reports readable `.icd` vendor manifests; on Windows it reports
registered OpenCL ICD libraries. It also records the `OCL_ICD_VENDORS` and
`OPENCL_VENDOR_PATH` overrides when set.

For every platform, the report provides profile/version/vendor and extensions.
For every device, it includes type, driver and language versions, extensions,
built-in kernels, memory/work-group/image limits, vector widths, FP feature
bitmasks, command queue/SVM/execution capabilities, compiler/linker state, and
other properties exposed by the runtime. If present, `clinfo` supplies a short
platform/device listing and its JSON output is retained only when that local
`clinfo` supports `--json`.

An unavailable optional OpenCL property is represented as `null` (and derived
bit-feature lists are also `null`), not as a negative capability claim.

The probe is read-only. It does not compile a kernel and cannot prove every
extension is usable with a particular application. ICD paths, platform names,
and device identifiers form machine inventory, so review the JSON before
sharing it outside a trusted context.
