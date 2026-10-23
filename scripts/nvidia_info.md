---
description: Cross-platform NVIDIA GPU and evidence-backed graphics-feature inspector.
---

# NVIDIA feature information tool

Run [`nvidia_info.py`](nvidia_info.py) to inspect NVIDIA GPUs and the local
driver evidence for CUDA, NVML, `nvidia-smi`, Vulkan ray-tracing extensions,
and NVENC/NVDEC codec-capacity APIs.

```sh
python scripts/nvidia_info.py --json
```

The stable JSON report has `schema_version`, `platform`, `availability`,
`driver`, `probes`, `devices`, and `limitations`. Each device has a
`capabilities` object for DLSS Super Resolution, DLSS Frame Generation, DLSS
Ray Reconstruction, Reflex, RTX ray tracing, Tensor Cores, NVENC, and NVDEC.
Every feature has three intentionally separate fields:

- `detection`: direct local evidence was found, or it is unknown.
- `support`: a relevant driver/API query exposed support, says not supported,
  or remains unknown.
- `eligibility`: only uses `likely_eligible_by_architecture` when CUDA's
  driver-reported compute capability provides a conservative architecture
  signal. It is never a confirmation.

NVENC/NVDEC are queried through NVML capacity APIs per GPU and codec. A
successful capacity query is driver evidence; an old driver rejecting an enum
is kept as raw evidence rather than misreported as missing hardware. CUDA
compute capability is used only for the Tensor Core eligibility hint. RTX ray
tracing requires both Vulkan ray-tracing extensions inside an NVIDIA
physical-device scope, rather than a product-name heuristic.

DLSS and NVIDIA Reflex are application features. GPU names, compute capability,
and a driver version cannot prove that an NGX or Reflex SDK call will
initialize. The tool reports locally visible NGX component files or Vulkan
low-latency extensions as detection evidence only, and leaves application
support unknown until a real application initializes it.

All probes are read-only and best effort, need only the Python standard
library, and work without the CUDA toolkit. Missing drivers/tools, remote
sessions, permissions, virtual GPUs, or a Vulkan JSON schema that cannot
scope extensions to the NVIDIA adapter produce `unknown`, not a negative
capability claim. The report may contain GPU UUIDs, PCI bus IDs, driver
versions, and local component paths; treat it as machine inventory before
sharing it.
