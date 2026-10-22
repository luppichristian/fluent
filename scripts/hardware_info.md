---
description: Cross-platform hardware inventory for chassis, memory, storage, graphics, networking, power, and sensors.
---

# Hardware information tool

Run [`hardware_info.py`](hardware_info.py) for a dependency-free, read-only
inventory of the current machine. It intentionally does not duplicate deep CPU
topology or instruction-set reporting; use [`cpu_info.py`](cpu_info.py) for
that information.

```sh
python scripts/hardware_info.py --json
```

Without `--json`, the script prints a compact summary. JSON output has a stable
top-level shape:

```text
{
  "platform": { "operating_system", "operating_system_release", "machine", "hostname" },
  "hardware": {
    "computer", "chassis", "baseboard", "bios", "memory", "storage",
    "filesystems", "graphics", "displays", "network", "battery", "sensors"
  }
}
```

Every hardware section is always present. Scalar values that a platform does
not expose are omitted and collection lists may be empty. The script uses
standard-library APIs plus safe optional native probes: Linux reads `/proc` and
`/sys` and may use `lsblk`, `lspci`, `xrandr`, and `dmidecode`; Windows uses
PowerShell/CIM; macOS uses `system_profiler`. Missing commands, headless
sessions, VMs, restricted containers, endpoint security, or permissions never
make the command fail.

Some details are deliberately best effort. Linux DIMM data often requires root
for `dmidecode`; GPU/display data depends on PCI and desktop-session access;
temperature/sensor data varies by driver; and macOS/Windows may report an
opaque or virtual adapter. Hardware serials and UUIDs can be sensitive—treat
JSON output as machine-identifying information and redact it before sharing.
