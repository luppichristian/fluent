---
description: Cross-platform operating system, runtime, and current-user inspector.
---

# System information tool

Run [`system_info.py`](system_info.py) for a read-only, cross-platform report
of the current operating system and signed-in user. It has no third-party
dependencies and uses best-effort operating-system probes: unavailable data is
represented as `null` (or an empty list) rather than making the command fail.

## Quick tool call

```sh
python scripts/system_info.py --json
```

The JSON report always has this top-level shape:

```text
{
  "operating_system": {
    "family", "distribution", "kernel_release", "kernel_version",
    "machine", "architecture"
  },
  "host": { "hostname", "fqdn", "addresses", "boot_time_utc", "uptime_seconds" },
  "resources": { "memory", "load_average", "working_directory_filesystem" },
  "locale": { "language", "encoding", "preferred_encoding", "timezone", "utc_offset_seconds" },
  "user": { "username", "uid", "gid", "groups", "home", "is_administrator" },
  "process": { "pid", "parent_pid", "runtime_seconds", "started_at_utc", "python" },
  "environment": { "included", "count", "redacted_count", "variables" }
}
```

On Windows `user.qualified_name` is also present; `uid` and `gid` are `null`.
On Unix, `groups` contains `{ "name", "id" }` objects; Windows reports group
names and types when `whoami` is available. The `process.runtime_seconds` is
the elapsed runtime of this script, not a machine uptime value.

## Privacy and environment values

Environment-variable values are **not collected or printed by default**.
They may contain credentials, proxy URLs, or other private context. Opt in only
when that information is intended for the recipient:

```sh
python scripts/system_info.py --json --include-environment
```

The opt-in output retains every variable name, but values with credential-like
names (for example `TOKEN`, `PASSWORD`, `SECRET`, `API_KEY`, any token-delimited
`KEY` such as `SERVICE_KEY`, `COOKIE`, `SESSION`, `HTTP_PROXY`, `DSN`, or
`CONNECTION_STRING`) are replaced with `***REDACTED***`. Other values longer
than 4096 characters are truncated. Redaction is a safety guard, not a
guarantee that a non-sensitive-looking variable cannot contain confidential
data.

Without `--json`, the tool prints a compact human-readable summary. Run
`python scripts/system_info.py --help` for the complete option list.
