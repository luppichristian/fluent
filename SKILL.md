---
name: fluent
description: Use for any work on C projects, including CUDA, GLSL/HLSL shaders, and assembly: writing code, debugging, testing, architecture, builds, releases, and project planning.
---

# fluent

You are working on a professional C project. The user is the product manager or technical lead.

## Resources

Load [JUMP.md](JUMP.md), it contains different types of resources:
- [procs](procs/): reusable procedures; they reference rules.
- [rules](rules/): focused rules and protocols; read only what applies.
- [subagents](subagents/): specific prompts for spawning subagents.
- [scripts](scripts/): generic, reusable crossplatform scripts and tooling.

Use it to find the resources you need, then open only the relevant `.md` files.

## Workflow

For every non-trivial user request:
1. Write a plan: goal, steps, files touched, optimal subagent delegation.
2. Split the plan into independent tasks. 
3. Give each task a goal, a scope, acceptance criteria, and its own files.
4. Spawn each subagent with it's relative task.
5. When a task is done, give it to a separate QA subagent. QA checks it against the acceptance criteria.
6. If QA finds a problem, send it back to the implementation subagent with QA's evidence. Then run QA again.
7. Mark a task complete only after QA approves. After all tasks pass, run QA once more on the combined result.

## Reporting

- Be precise about what is complete, what remains, known limitations, temporary measures, and whether validation occurred. 
- Do not hide uncertainty or describe unverified work as complete.

## Keep the project clean

- Minimal changes are always preferred.
- Edit an existing file instead of creating a new one.
- Delete unused and duplicate files.
- Follow the existing folder layout and naming.

## Project stage

Check the project stage and follow it:

| Stage | What to do |
|---|---|
| Early Development | Keep it simple. Get to a first working build. |
| Deep Development | Prioritize quality and performance. |
| Closed Release | Start versioning. Big changes are still allowed. |
| Public Release | Use strict versioning. Be careful with big changes. |

Before Public Release, ignore backwards compatibility.

## Skill growth

When your work produces a reusable resource that is proven to work:
1. Search the existing resources first. If one fits, extend it. Otherwise create one new file.
2. Put it in the right folder: `scripts/`, `tasks/`, `rules/`, `subagents/`.
3. Add name and description metadata to the file, then add its entry to `JUMP.md` by hand.
4. Test any script you changed.

Do not save task-specific details or guesses. Keep the number of resources small, because every entry in `JUMP.md` uses context.

## Remember

Plan, delegate, verify with QA, report honestly.

Always try to satisfy the user's request in the most complete and optimal way.