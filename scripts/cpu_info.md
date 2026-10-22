---
description: Cross-platform CPU hardware, instruction-set, cache, and utilization inspector.
---

# CPU information tool

Run [`cpu_info.py`](cpu_info.py) to inspect the current machine's CPU without
requiring third-party packages. It reports the CPU identity, platform and
architecture, logical and physical core counts (where the OS exposes them),
frequency/cache data, supported instruction sets, and a short CPU-usage
sample. The output adapts to the data each operating system makes available.

## Quick tool call

```sh
python scripts/cpu_info.py --json
```

The JSON object has a stable top-level shape:

```text
{
  "platform": { "operating_system", "operating_system_release", "machine", ... },
  "cpu": {
    "name", "vendor", "physical_cores", "logical_cores", "frequency_mhz",
    "cache", "instruction_sets", "usage"
  }
}
```

Use `--no-usage` when only static hardware details are wanted, or
`--interval 1` to collect usage over one second. Without `--json`, it prints a
compact human-readable report. `--help` lists all options.

If `psutil` happens to be installed, it is used for a richer usage and frequency reading,
but it is optional. CPUID flags indicate processor capabilities; software must
also check operating-system support before using stateful extensions such as
AVX or AVX-512.
