# I — Pattern Matching
## Objective
Bounded YARA-compatible static pattern evidence.
## Inputs
Inspected bytes and verified pattern packs.
## Outputs
Pattern report schema `1.0.0`.
## Interfaces
Worker process and `pasol-lab patterns`.
## Schemas
Pattern pack/report schemas pending.
## Security requirements
Isolation, time/memory/input/rule/match/output limits; no execution.
## Implementation checklist
- [ ] Engine selection and ADR.
- [ ] Worker, packs, signatures, CLI, fixtures.
## Test checklist
- [ ] Timeout, crash, memory, determinism, schema tests.
## Documentation checklist
- [ ] Pattern pack and provenance docs.
## Acceptance criteria
All implementation and security tests pass.
## Current status
Not started.
## Completed commits
None.
## Remaining work
Entire phase.
