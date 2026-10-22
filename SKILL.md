---
name: fluent
description: Develop professional C projects, including targeted CUDA, shader, and assembly work.
---

# fluent

Protocols for professional C projects, including targeted CUDA, GLSL/HLSL, and assembly work. 
The user is the product manager or technical lead.

## Areas

- Implementation: code, patterns, conventions, and style.
- Project design: structure and boundaries.
- Architecture: system design in code.
- Debugging and testing: unit, integration, end-to-end, and coverage where useful.
- Distribution: supported platforms and release work.
- Project management: planning, scope, status, and delivery.

## Resources

- [tasks](tasks/): reusable procedures; check for matching tasks in the user's request and apply instructions.
- [rules](rules/): focused rules and protocols; read only what applies.
- [subagents](subagents/): specific prompts for spawning subagents.
- [scripts](scripts/): generic, reusable scripts and tooling.

Load [JUMP.md](JUMP.md) and use it to find resources by name and description, then open only the relevant resources.

The user's request is parsed into tasks.
Subagents can spawn other subagents. 
Subagents perform tasks.
Tasks can generate subagents.

## Working standard

For every user request, make a proportional plan and split it into independent tasks. Assign each task to an implementation subagent, separating ownership and write targets as much as possible to prevent conflicts. Assign separate quality-manager subagents to independently verify each result and the integrated outcome. If QA finds a defect or unmet requirement, return it to the responsible implementation subagent, then repeat QA; only QA-approved work is complete. Aim for production-ready work unless the user requests otherwise. Be exact about completed and remaining work, limitations, temporary measures, and whether a result is minimal or production-ready. Never hide uncertainty or present unverified work as complete.

## Skill growth

When work produces a proven, likely-reusable asset, update this skill as part of the work: operations go in `scripts/`, procedures in `tasks/`, durable rules in `rules/`, and delegation patterns in `subagents/`. Add its description metadata and manually update its entry in `JUMP.md`. Search first and extend a compatible resource rather than duplicating it; create a focused file only when it has distinct future value. Do not save task-specific details or speculation. Preserve callers and validate changed scripts.
