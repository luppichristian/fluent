---
description: Read-only report of system, hardware, and CPU capabilities.
---

# Machine tool

Collects a read-only, cross-platform snapshot of the current machine. Run it to give a person or an LLM the OS, hardware, CPU, and (when explicitly requested) runtime/build facts needed to diagnose compatibility, capacity, or performance issues.

## What it reports

- **System:** OS/distribution, host/boot, user, locale, and process details; memory, load, and the working filesystem. Environment values are opt-in.
- **Hardware:** computer, chassis, baseboard, BIOS, memory modules, disks/filesystems, graphics adapters/displays, network adapters, battery, and sensors when the host exposes them.
- **CPU:** model/architecture, physical and logical topology, frequency, cache, instruction sets, and an optional utilization sample.
- **Developer context (opt-in):** effective CPU/memory limits, explicit container/WSL/VM/remote-session evidence, fixed compiler/runtime/package-manager version probes, CPU NUMA/power/virtualization/OS-visible ISA evidence, and richer interface/route/DNS and display-connector data where the platform exposes it.

## Run

```sh
python scripts/machine_info.py --json
python scripts/machine_info.py --sections hardware,cpu --json
python scripts/machine_info.py --sections cpu --no-usage
python scripts/machine_info.py --developer-context --profile llm --redact default --json
```

## Options

| Option | Default | Effect |
| --- | --- | --- |
| `--json` | off | Full formatted JSON; otherwise concise overview. |
| `--sections LIST` | `system,hardware,cpu` | Select `system`, `hardware`, `cpu`; repeatable; comma lists, case-insensitive, deduplicated. |
| `--include-environment` | off | Opt-in environment; needs `system`. |
| `--developer-context` | off | Add fixed, read-only runtime-limit, toolchain, CPU-suitability, network, and display probes. |
| `--no-usage` | off | Skip CPU sampling; needs `cpu`. |
| `--interval SECONDS` | `0.2` | Non-negative sample seconds; needs `cpu`; conflicts with `--no-usage`. |
| `--profile full\|llm\|summary` | `full` | Full evidence, or a bounded machine-readable decision summary for LLM/tool use. |
| `--redact none\|default\|strict` | `none` | Redact local identifiers before printing or saving. Use at least `default` before sharing. |
| `--requirements PATH` | off | Evaluate a JSON compatibility manifest against the full report. |
| `--compare PATH` | off | Add a bounded diff against a prior JSON snapshot. |
| `--save PATH` | off | Save the final redacted report as a JSON snapshot. |
| `--envelope` | off | Wrap full evidence in the common `tool`/`status`/`metadata` envelope without changing the default legacy shape. |
| `--output-schema` | off | Print the shared requirements-manifest schema and exit without collecting. |
| `--report-schema` | off | Print the Draft 2020-12 JSON Schema for legacy or enveloped machine reports. |
| `-h`, `--help` | n/a | Help, then exit. |

Repeated `--sections` values are combined; valid names are `system`, `hardware`, and `cpu`. Invalid/empty selections, negative intervals, or incompatible options exit non-zero.

## Output

`--json` emits one stable object: `schema_version`, `platform`, `selected_sections`, and `sections`. The default full report preserves this historic shape. Any shared output control (`--profile`, `--redact`, `--requirements`, `--compare`, or `--save`) also adds transport metadata. `sections` contains only the requested `system`, `hardware`, and/or `cpu` reports. `--developer-context` adds a separate `developer_context` object so existing section paths remain unchanged. It has explicit `status` and `source` fields on each new probe: `available`, `unavailable`, `unsupported`, `failed`, or `unknown` never means a negative compatibility result. Without `--json`, the tool prints a compact overview.

Unavailable facts remain `null`, empty, or omitted where the embedded probe contract permits them; they are not treated as a negative capability.

## Notes

Probes are local, read-only, and best-effort. The default CPU sample takes about 0.2 seconds; `--developer-context` also makes fixed local version/CIM/platform queries and can take several seconds. It does not compile code, install packages, contact the network, test a GPU/audio workload, or prove an application can use a reported ISA/API.

Restricted, virtualized, headless, or tool-limited hosts can expose less data. Linux has the richest cgroup/NUMA/cpufreq/DRM and route data. Windows enriches runtime, CPU, network, and monitor data through read-only PowerShell CIM queries plus Job Object limits and NUMA processor-group APIs. Other platforms retain explicit `unsupported` or `unknown` results instead of inferred capability.

Reports can contain host, user, network, device, storage, graphics, model, serial, executable, and tool-path data. Environment output redacts credential-like names and truncates long values, but is not a substitute for secret scrubbing. Use `--redact default` before sharing; `strict` also removes many identifying names, paths, and identifiers and can make some nested raw evidence opaque.
