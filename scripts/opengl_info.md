---
description: Read-only OpenGL runtime, extension, capability, and framebuffer configuration inspector.
---

# OpenGL information tool

Run `python scripts/opengl_info.py --json` to obtain a machine-readable
OpenGL report. Its stable top-level shape is `platform` and `opengl`; the
OpenGL section always includes `available`, `tools`, `runtime`, `extensions`,
`capabilities`, `configurations`, `probes`, and `limitations`.

On Linux and other GLX hosts, the optional `glxinfo -l` probe supplies the
renderer, driver/API strings, full advertised GL/GLX/EGL extension names,
reported `GL_*` limits, and raw FBConfig rows. `eglinfo`, if available, is
captured as a bounded EGL summary. The probe only reads system state and never
creates a persistent configuration.

Windows and macOS ship an OpenGL loader/framework, but neither exposes a
portable command-line context inspector. The script reports that loader only
as a hint and leaves `available` as `unknown` unless `glxinfo` successfully
queries a renderer. Headless, remote, sandboxed, or driver-restricted sessions
can prevent context creation even when applications can render elsewhere.
