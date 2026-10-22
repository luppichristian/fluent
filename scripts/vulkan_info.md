---
description: Read-only Vulkan loader, instance, device, layer, extension, and capability inspector.
---

# Vulkan information tool

Run `python scripts/vulkan_info.py --json` for a read-only Vulkan report. The
stable top level contains `platform` and `vulkan`; Vulkan always includes
`available`, `tools`, `loader_paths`, `summary`, `details`, `probes`, and
`limitations`.

If the optional Vulkan SDK utility `vulkaninfo` is available, the script runs
`vulkaninfo --json` in a private temporary directory (some Windows SDK
versions otherwise write a `VP_VULKANINFO_*.json` file to the current
directory). Its complete decoded result is retained in `details`,
which allows an LLM to inspect the installed SDK's layers, extensions,
physical-device properties, feature chains, queues, memory heaps, formats,
surface support, limits, and driver/ICD-specific configuration without a
lossy parser. `summary.runtime` preserves a parsed and raw `vulkaninfo
--summary` view of instance extensions/layers and physical-device identity;
`summary.selected_fields` duplicates commonly useful JSON fields with their
paths for quick scans.

Output can be large on feature-rich drivers. Vulkaninfo schemas vary across
SDK versions, and headless systems may lack WSI/surface data. A loader DLL or
shared library only means the loader was found—not that an ICD, permission, or
physical GPU is usable. Missing tools, failed instance enumeration, and macOS
portability-layer requirements are recorded in `limitations` and `probes`.
