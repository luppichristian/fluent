---
description: Read-only cross-platform report of system, hardware, and CPU capabilities.
---

# Machine tool

Collects a read-only, cross-platform snapshot of the current machine. Run it to give a person or an LLM the OS, hardware, and CPU facts needed to diagnose compatibility, capacity, or performance issues.

## What it reports

- **System:** OS/distribution, host/boot, user, locale, and process details; memory, load, and the working filesystem. Environment values are opt-in.
- **Hardware:** computer, chassis, baseboard, BIOS, memory modules, disks/filesystems, graphics adapters/displays, network adapters, battery, and sensors when the host exposes them.
- **CPU:** model/architecture, physical and logical topology, frequency, cache, instruction sets, and an optional utilization sample.

## Run

```sh
python scripts/machine_info.py --json
python scripts/machine_info.py --sections hardware,cpu --json
python scripts/machine_info.py --sections cpu --no-usage
```

## Options

| Option | Default | Effect |
| --- | --- | --- |
| `--json` | off | Full formatted JSON; otherwise concise overview. |
| `--sections LIST` | `system,hardware,cpu` | Select `system`, `hardware`, `cpu`; repeatable; comma lists, case-insensitive, deduplicated. |
| `--include-environment` | off | Opt-in environment; needs `system`. |
| `--no-usage` | off | Skip CPU sampling; needs `cpu`. |
| `--interval SECONDS` | `0.2` | Non-negative sample seconds; needs `cpu`; conflicts with `--no-usage`. |
| `-h`, `--help` | n/a | Help, then exit. |

Repeated `--sections` values are combined; valid names are `system`, `hardware`, and `cpu`. Invalid/empty selections, negative intervals, or incompatible options exit non-zero.

## Output

`--json` emits one stable object: `schema_version`, `platform`, `selected_sections`, and `sections`. `sections` contains only the requested `system`, `hardware`, and/or `cpu` reports. Without `--json`, the tool prints a compact overview.

Unavailable facts remain `null`, empty, or omitted where the embedded probe contract permits them; they are not treated as a negative capability.

## Notes

Probes are local, read-only, and best-effort. The default CPU sample takes about 0.2 seconds; restricted, virtualized, headless, or tool-limited hosts can expose less data. Reports can contain host, user, network, device, storage, graphics, model, or serial data. Environment output redacts credential-like names and truncates long values, but is not a substitute for secret scrubbing.
