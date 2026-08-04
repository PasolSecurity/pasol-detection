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
Pattern pack/report and worker schemas are versioned at `1.0.0`.
## Security requirements
Isolation, time/memory/input/rule/match/output limits; no execution.
## Implementation checklist
- [x] I0 engine selection, ADR, dependency pin, Windows compatibility, and Rust 1.91 verification. Evidence: `../TEST-EVIDENCE.md#2026-08-04-phase-i0-msrv-and-i1-contracts`.
- [~] I1 versioned contracts, schemas, runtime validation, deterministic ordering, and bounds.
- [ ] I2–I9 signed packs, compiler, worker, CLI, goldens, fuzzing, hosted CI, and acceptance.
## Test checklist
- [~] I1 status, schema, bounds, path, ordering, and serialization tests.
- [ ] Worker, timeout, crash, memory, scanner, trust, and hosted tests.
## Documentation checklist
- [x] Engine ADR and compatibility policy.
- [ ] Pattern pack, worker, limits, report, privacy, and threat-model docs.
## Acceptance criteria
All implementation and security tests pass with deterministic schema-valid evidence.
## Current status
I0 is accepted. I1 contracts and schemas are active; compiler, signing, worker, CLI, and file scanning remain unstarted.
## Completed commits
`58e20ed` (I0 compatibility baseline).
## Remaining work
Complete I1 schema/golden evidence, then begin I2 signed pattern-pack validation.
