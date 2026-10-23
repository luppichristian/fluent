---
description: Inspect the local OpenAL runtime, its output devices, extensions, and default-device capabilities.
---

# Audio tool

`audio_info.py` is a read-only OpenAL diagnostic: whether the local loader can
be used and its reported output devices/capabilities. It is not a speaker,
microphone, or application-audio test.

## What it reports

- Candidate/loaded OpenAL library and load attempts.
- Global ALC extensions, default playback device, and enumeration-supported
  playback/all devices.
- A temporary default-device context: ALC/device data, source limits,
  extensions, vendor/renderer/version, and HRTF.
- Optional `openal-info` output. It does not enumerate capture devices or test
  recording.

## Run

```sh
python scripts/audio_info.py
python scripts/audio_info.py --json
python scripts/audio_info.py --json --no-context
python scripts/audio_info.py --json --include-openal-info
```

## Options

| Flag | Default | Effect |
| --- | --- | --- |
| `--json` | off | Emit stable, pretty JSON instead of the short summary. |
| `--no-context` | off | Do not open and close the default output device. |
| `--include-openal-info` | off | Run local `openal-info` (25 s limit) and include its output or failure. |
| `-h`, `--help` | n/a | Show usage without probing. |

Flags combine; there are no positional arguments. Unknown flags exit `2`.

## Output

JSON has `schema_version`, `platform`, and `audio`. The complete report is
`audio.openal`: `available`, `library`, `global`, `context`, `native_tool`, and
`limitations`. `available: true` means the runtime loaded; it does not confirm
that every listed feature works with every device.

## Notes

No network, installation, or configuration changes occur. By default it briefly
creates then destroys a silent context; use `--no-context` where unsuitable.
Device names and native-tool output are local metadata. Missing libraries or
devices, restricted/headless/remote sessions, and failures are evidence.
