---
description: Public audio capability entry point that preserves the complete OpenAL report.
---

# Audio information tool

Run [`audio_info.py`](audio_info.py) for the public audio capability report:

```sh
python scripts/audio_info.py --json
```

It contains a self-contained OpenAL probe. The facade does not merge or rename
OpenAL fields: `audio.openal` is the complete report from that embedded probe.
As more audio probes are added, each belongs under a separate `audio` child
rather than being flattened into a potentially ambiguous shared capability
list.

## Command arguments

| Argument | Default | Effect |
| --- | --- | --- |
| `--json` | off | Prints one stable, pretty-printed JSON object. Without it, the command prints a short human-readable summary. |
| `--no-context` | off | Passes `probe_context=False` to OpenAL. It still finds and loads an OpenAL library and queries global device enumeration where possible, but never opens the default audio device or creates an OpenAL context. |
| `--include-openal-info` | off | Passes `include_openal_info=True` to OpenAL. If the optional `openal-info` executable is on `PATH`, its unparsed output lines are included at `audio.openal.native_tool`; otherwise that object records that it was unavailable. |
| `-h`, `--help` | n/a | Shows argparse help and exits without probing. |

Examples:

```sh
# Fast, machine-readable inventory with no audio-device open.
python scripts/audio_info.py --json --no-context

# Default concise summary. The context probe is enabled.
python scripts/audio_info.py

# Include optional native implementation diagnostics in JSON.
python scripts/audio_info.py --json --include-openal-info
```

Unknown arguments are rejected by the command with an exit status of 2. The
flags may be combined in any order. There are no positional arguments.

## JSON output contract

The top-level JSON object has this stable shape:

```json
{
  "schema_version": 1,
  "platform": {
    "operating_system": "...",
    "release": "...",
    "machine": "..."
  },
  "audio": {
    "openal": {
      "available": false,
      "library": {},
      "global": {},
      "context": {},
      "native_tool": null,
      "limitations": []
    }
  }
}
```

`schema_version` describes the facade. `platform` comes from the embedded
OpenAL probe. `audio.openal` preserves all fields and nullable values from
that probe without a lossy merge. In particular, inspect
`audio.openal.library`, `audio.openal.global`, and `audio.openal.context` for
probe evidence rather than treating `available` as proof that every feature is
usable.

## Privacy, cost, and limitations

The tool uses only the Python standard library and makes no network requests,
uploads, package installations, or configuration changes. It reads local
library/device metadata. By default it briefly opens the default OpenAL output
device to query renderer and extension information, then destroys the context
and closes the device; it does not play sound or create audio sources. Use
`--no-context` where even a short device open is undesirable.

`--include-openal-info` starts the local optional `openal-info` program and
captures its combined output, with a 25-second timeout in the underlying
probe. That output may contain implementation-specific device names or
diagnostics, so treat it as local-machine information before sharing a report.
The default context probe can fail in headless, permission-restricted, remote,
or audio-server-limited environments; such failure is reported as evidence,
not guessed away. An OpenAL runtime/device report cannot prove physical audio
hardware support, OS mixer configuration, application sound output, or game
audio features.
