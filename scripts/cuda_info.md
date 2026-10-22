---
description: Cross-platform CUDA driver, toolkit, and NVIDIA GPU capability inspector.
---

# CUDA information tool

Run [`cuda_info.py`](cuda_info.py) to report the CUDA driver/API, NVIDIA GPU
limits, toolkit/compiler installation, and `nvidia-smi` telemetry without
requiring a CUDA Python package or the CUDA toolkit.

```sh
python scripts/cuda_info.py --json
```

The stable top-level JSON object is `schema_version`, `platform`,
`availability`, `probes`, `installations`, `driver`, and `devices`.  The
`probes` section always explains whether the CUDA Driver API, `nvidia-smi`, and
`nvcc` were found and usable.  A system can therefore expose useful hardware
limits through its display driver even when it has no compiler installed.

For each driver-enumerated GPU, `devices` includes compute capability, global
memory, and core scheduling/memory limits such as SM count, warp size, block
and grid limits, registers, shared/constant memory, addressing and managed
memory features. `nvidia-smi` adds UUID/PCI/VBIOS identity, driver version,
free/used memory, temperature, power limit, performance state, and compute
configuration when the installed `nvidia-smi` version supports those fields.

This is read-only and best effort. CUDA is normally unavailable on macOS and
on hosts without an NVIDIA driver; a successful script run does not imply that
CUDA compilation or a workload will succeed. The report includes locally
configured CUDA paths, GPU UUIDs, PCI addresses, and device serial-adjacent
metadata; treat a JSON report as machine inventory when sharing it.
