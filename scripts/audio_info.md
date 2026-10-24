---
description: Inspect OpenAL plus passive operating-system playback and capture endpoint inventories.
---

# Audio tool

`audio_info.py` is a read-only audio evidence collector. It preserves its
OpenAL runtime report and adds the local operating system's passive endpoint
inventory where it is safely observable. It does not claim that an application
can initialize every backend or that a listed microphone can record.

## What it reports

- Candidate/loaded OpenAL library and load attempts, playback device lists,
  extensions, default-device context configuration, and HRTF evidence.
- Windows: PnP `AudioEndpoint` records used by WASAPI: render/capture
  direction, endpoint state, PnP driver provider/version, and the user-level
  microphone-consent default where exposed.
- macOS: CoreAudio-related `system_profiler SPAudioDataType` inventory.
- Linux: PipeWire (`pw-dump`), PulseAudio (`pactl -f json`), and ALSA procfs
  inventories. These may coexist; unavailable daemons are reported separately.
- Every OS backend has a `status`, source-labelled `provenance`, structured
  `errors`, `limitations`, and `data`, so absence, an unsupported OS, denied
  access, a failed command, and an unknown fact are not conflated.
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
python scripts/audio_info.py --json --endpoint-formats
python scripts/audio_info.py --json --profile llm --redact default
python scripts/audio_info.py --json --smoke-test openal-default-context
```

## Options

| Flag | Default | Effect |
| --- | --- | --- |
| `--json` | off | Emit stable, pretty JSON instead of the short summary. |
| `--no-context` | off | Do not open and close the default output device. |
| `--include-openal-info` | off | Run local `openal-info` (25 s limit) and include its output or failure. |
| `--no-os-audio` | off | Skip passive OS-audio inventory, retaining only OpenAL. |
| `--endpoint-formats` | off | On Windows, activate `IAudioClient` only long enough to read shared-mode `GetMixFormat` data for default endpoints. It neither initializes a stream nor plays/captures. |
| `--smoke-test none\|openal-default-context` | `none` | Run an explicitly requested safe test. `openal-default-context` opens then destroys the default OpenAL context and never renders or captures audio. |
| `--profile full\|llm\|summary` | `full` | Select complete evidence or a compact bounded LLM/terminal summary. |
| `--redact none\|default\|strict` | `none` | Replace share-sensitive endpoint labels and identifiers before output/saving. Use `default` before sharing; `strict` also replaces more descriptive metadata. |
| `--requirements PATH` | off | Evaluate a JSON requirements manifest against the unfiltered full report. Missing evidence is `unknown`, never a pass. |
| `--compare PATH` | off | Include a bounded structural comparison with a prior JSON snapshot. |
| `--save PATH` | off | Save the final redacted JSON report as a snapshot. |
| `--envelope` | off | Wrap full evidence in the common `tool`/`status`/`metadata` envelope; omitted by default for compatibility. |
| `--output-schema` | off | Print the requirements-manifest schema and exit without probing. |
| `--report-schema` | off | Print the Draft 2020-12 JSON Schema for legacy or enveloped audio reports. |
| `-h`, `--help` | n/a | Show usage without probing. |

Flags combine; there are no positional arguments. Unknown flags exit `2`.

## Output

JSON has `schema_version`, `platform`, and `audio`. `audio.openal` retains the
historic OpenAL fields (`available`, `library`, `global`, `context`,
`native_tool`, and `limitations`). New evidence is in
`audio.platform_backends.<backend>` and uses the common probe shape. Endpoint
records hold a name, render/capture direction, optional identifier/state,
default roles, formats/layouts, driver evidence, and metadata. A field being
empty or `null` means the selected passive probe did not establish it; consult
the backend `status`, `errors`, and `limitations` before interpreting it.

`--profile llm` and `--profile summary` emit counts, status, defaults, and
error codes rather than raw endpoint records. The default `full` profile keeps
the complete backwards-compatible evidence report. Built-in portable output
controls add `metadata`, and can add `compatibility` and `comparison` results;
the script has no runtime dependency on another Fluent file.

## Notes

No network, installation, configuration, playback, or capture changes occur.
For historic compatibility, the default OpenAL probe briefly creates then
destroys a silent context; use `--no-context` where unsuitable. This is not the
new explicit smoke-test mode. Device names, PnP identifiers, and native-tool
output are local metadata; use redaction before sharing.

The Windows inventory uses `IMMDeviceEnumerator` to report default endpoint
roles. `--endpoint-formats` additionally activates `IAudioClient` only to read
default shared-mode mix formats; exclusive modes, arbitrary endpoints, and
actual stream initialization remain outside its scope. It reports only
the user-level microphone-consent default, not each application's grant. The
macOS inventory does not open `AudioObject`/`AudioUnit`, but preserves any
default-endpoint and format details supplied by `system_profiler`.
Linux portal grants and device-node ACLs are likewise not inferred from daemon
or procfs state. OpenAL context creation and OS endpoint enumeration are not a
playback, recording, latency, underrun, codec, spatial-audio, or application
backend compatibility test.
