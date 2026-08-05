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
- [x] I1 versioned contracts, schemas, runtime validation, deterministic ordering, bounds, proof-boundary checks, and twelve deterministic goldens. Evidence: `../TEST-EVIDENCE.md#2026-08-04-i1-proof-boundary-and-golden-corpus`.
- [x] I2 signed pattern-pack validation, shared trust layer, exact-byte source hashing, detached signatures, bounded bundle verification, fixtures, and local tests. Evidence: `../TEST-EVIDENCE.md#2026-08-05-hosted-i2-contract-verification`.
- [x] I3 detailed compiler-adapter planning specification. Evidence: `I3-COMPILER-ADAPTER.md`.
- [ ] I3 compiler-adapter implementation and acceptance.
- [ ] I4 isolated worker process and resource enforcement.
- [ ] I5 pattern CLI and starter pack.
- [ ] I6-I9 hosted fuzz campaigns, release evidence, and final acceptance.
## Test checklist
- [x] I1 status, schema, bounds, path, ordering, serialization, mutation, and golden tests.
- [x] I2 trust, manifest, source, key-state, signature, and bundle verification tests.
- [ ] Worker, timeout, crash, memory, scanner, and hosted fuzz-campaign tests.
## Documentation checklist
- [x] Engine ADR and compatibility policy.
- [x] Pattern-pack trust, exact-byte hashing, privacy, and threat-model documentation.
- [ ] Worker, limits, report, and compiler documentation.
## Acceptance criteria
All implementation and security tests pass with deterministic schema-valid evidence.
## Current status
I0, I1, and I2 are accepted at the contract/trust foundation level. I3 planning is complete, but compiler implementation remains inactive.
## Completed commits
`58e20ed` (I0 compatibility baseline), `8f827cf` (I1 contracts), `179ee7f` (I1 hardening), `53ad196` (I1 proof/golden closure), `df80c50` (I2 activation), `07546b3` (shared trust), `57aa637` (manifest/signing), `dc38558` (fixtures/goldens), and `b4aa3e7` (hosted contract evidence).
## Remaining work
Obtain explicit approval to activate I3 implementation; do not modify production code before activation.
