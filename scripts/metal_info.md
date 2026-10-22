---
description: Read-only macOS Metal device, driver, toolchain, and capability inventory.
---

# Metal information tool

Run `python scripts/metal_info.py --json` to produce a read-only report. Its
stable top level contains `platform` and `metal`; the Metal section always has
`available`, `tools`, `toolchain`, `devices`, `details`, `probes`, and
`limitations`.

On macOS, the script obtains complete `SPDisplaysDataType`, hardware, and
software records from `system_profiler` and preserves them in
`details.system_profiler`. `devices` is the display-adapter inventory, while
`details.metal_related_fields` makes profiler fields mentioning Metal, GPU
families, or feature sets easy to locate. When Xcode command-line tools are
present, it also records the Metal compiler location/version and Xcode version.
`details.display_adapter_inventory_available` says only that macOS enumerated
one or more display adapters; it is not Metal availability.

Metal has no general command-line equivalent to `vulkaninfo`; exact
`MTLDevice` feature families, texture formats, numeric limits, performance
counters, and runtime configurations require a native Metal process. The
script deliberately does not infer those values—or Metal availability—from a
GPU name or a `system_profiler` adapter entry. Consequently `available` is
`unknown` on macOS until a native Metal probe confirms device creation. On
non-macOS platforms it returns a successful unsupported report rather than
attempting a compatibility-layer probe.
