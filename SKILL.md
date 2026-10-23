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
- [scripts](scripts/): generic, reusable crossplatform scripts and tooling.

Load [JUMP.md](JUMP.md) and use it to find resources by name and description, then open only the relevant resources.

## Working standard

For every non-trivial user request:
1. Make a plan proportional to the request.
2. Split the work into independent tasks whenever it can be split safely.
3. Assign each task to an implementation subagent. Give every task a clear goal, scope, and acceptance criteria. Keep file ownership separate where possible to avoid conflicts.
4. Assign separate quality-manager subagents to verify each completed task and the integrated result independently.
5. If QA finds a defect or an unmet requirement, return the task to its implementation subagent with the QA evidence. Run QA again after the fix.
6. Mark work complete only after QA approves it.

Implementation subagents perform their assigned tasks. Subagents may spawn other subagents. Tasks may generate subagents.

Aim for production-ready work unless the user requests a smaller or temporary result. Be precise about what is complete, what remains, known limitations, temporary measures, and whether validation occurred. Do not hide uncertainty or describe unverified work as complete.

Work always needs to be audited and tested.

## Skill growth

When work produces a proven, likely-reusable asset, update this skill as part of the work: operations go in `scripts/`, procedures in `tasks/`, durable rules in `rules/`, and delegation patterns in `subagents/`. Add its description metadata and manually update its entry in `JUMP.md`. Search first and extend a compatible resource rather than duplicating it; create a focused file only when it has distinct future value. Do not save task-specific details or speculation. Preserve callers and validate changed scripts.
