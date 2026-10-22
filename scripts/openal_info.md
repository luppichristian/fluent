---
description: Cross-platform OpenAL runtime, device, extension, and context inspector.
---

# OpenAL information tool

Run [`openal_info.py`](openal_info.py) to inspect a locally installed OpenAL
implementation with no third-party Python packages:

```sh
python scripts/openal_info.py --json
```

The report has stable `platform` and `openal` sections.  It records shared
library candidates and every load attempt, global device-enumeration extensions,
default devices, enumerated playback devices, and ALC extensions.  When a
default device can be opened, it temporarily creates an OpenAL context and
reports the exact vendor, renderer, version, AL/ALC extensions, source limits,
frequency/refresh configuration, and the HRTF capability/specifier list when
the implementation exposes `ALC_SOFT_HRTF`.

The JSON schema preserves initialized nullable leaves. For example, an
unavailable library reports `openal.library.loaded_path: null` and
`openal.context.failure: null`; empty arrays and objects remain present as
well. This lets an LLM distinguish a failed/unavailable probe from a missing
field.

The default context probe does not play sound, create sources, or retain an
audio device: it opens the default device only long enough to query the API,
then destroys the context and closes the device.  Use `--no-context` in a
headless, permission-restricted, or audio-sensitive environment.  Use
`--openal-info` to append the unparsed output lines from the optional native
`openal-info` utility; this may provide implementation-specific diagnostics.

OpenAL is optional on every platform.  A missing library, failed device open,
or an extension not exposed by the implementation is represented explicitly in
`openal.library`, `openal.context.failure`, and `openal.limitations`, never
guessed from the OS or hardware name.
