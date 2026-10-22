---
description: Windows Direct3D runtime, adapter, driver, and DxDiag inspector.
---

# Direct3D information tool

Run [`direct3d_info.py`](direct3d_info.py) to inspect the Direct3D-related
information exposed by Windows, without third-party packages:

```sh
python scripts/direct3d_info.py --json
```

The report has a stable `platform` and `direct3d` top-level shape.  On Windows
it contains CIM display-adapter/driver properties, the DirectX registry values
that exist, the Windows version, and Direct3D-relevant DxDiag key/value
sections. The latter preserves DxDiag's original field names because they follow the Windows display
language.  When an English-style `Feature Levels` field is present, the script
also copies its values to `direct3d.feature_levels`.

DxDiag is the only probe that writes a file: it writes a temporary text report,
the script reads it, then removes it.  Use `--skip-dxdiag` to avoid launching
it.  The tool does **not** create a Direct3D device, compile shaders, or claim
feature levels based on a GPU name.  Missing output, localised field names,
permissions, remote sessions, and virtual GPUs can therefore leave fields
empty; see `direct3d.limitations` and `direct3d.dxdiag.source` for evidence.

On Linux, macOS, and other non-Windows hosts it returns the same top-level
shape with `supported_platform: false` and an explicit limitation instead of
trying a compatibility layer such as Wine.
