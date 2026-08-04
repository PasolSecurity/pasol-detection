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
Pattern pack/report and worker schemas are planned for I1; no production schemas are added in I0.
## Security requirements
Isolation, time/memory/input/rule/match/output limits; no execution.
## Implementation checklist
- [~] Engine selection, ADR, dependency pin, and Windows compatibility spike. MSRV 1.91 verification is blocked pending the exact toolchain.
- [ ] Worker, packs, signatures, CLI, fixtures.
## Test checklist
- [ ] Timeout, crash, memory, determinism, schema tests.
## Documentation checklist
- [ ] Pattern pack and provenance docs.
## Acceptance criteria
All implementation and security tests pass.
## Current status
I0 is active. Production pattern functionality remains unstarted.
## Completed commits
None.
## Remaining work
Complete Rust 1.91 compatibility verification, then begin I1 typed contracts and schemas.
