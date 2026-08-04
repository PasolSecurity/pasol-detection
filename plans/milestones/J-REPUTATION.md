# J — Reputation
## Objective
Provider-independent offline-first hash evidence.
## Inputs
SHA-256 hashes.
## Outputs
Reputation schema `1.0.0`.
## Interfaces
Provider trait, local store, mock provider, CLI.
## Schemas
`reputation-report-1.0.0.schema.json` and `local-reputation-store-1.0.0.schema.json` are the J1 targets.
## Security requirements
No uploads by default; unknown/unavailable remain distinct; secrets redacted.
## Implementation checklist
- [x] J1 provider contract, descriptors, states, report types, and runtime schemas.
- [x] J2 offline local provider.
- [x] J3 persistent store.
- [x] J4 cache and expiration semantics.
- [x] J5 CLI and integration tests, including typed exit classes and schema-valid JSON errors. Evidence: `../TEST-EVIDENCE.md#2026-08-04-typed-reputation-cli-errors`; Commit `210eeff`.
- [x] J6 deterministic goldens and schema-drift CI are verified. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-goldens-and-schema-drift-gate`; Commit `1253639`.
- [x] J7 bounded property tests, fuzz targets, corpus replay, and hosted smoke campaigns. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-property-invariants`, `../TEST-EVIDENCE.md#2026-08-04-reputation-fuzz-target-compilation`, `../TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`.
## Test checklist
- [x] Offline, conflict, expiry, schema, import/export, and first actual-binary CLI tests.
- [x] Typed JSON-error and exit-class matrix.
## Documentation checklist
- [x] Provider, store, privacy, and threat-model docs. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-documentation-closure`; Commit `14d9849`.
## Acceptance criteria
All provider and offline tests pass.
## Current status
J1–J4 are verified at the core level; final J5/J6 evidence remains. No network or remote-provider implementation exists.
## Completed commits
None.
## Remaining work
Select and record the next milestone explicitly before beginning Phase I or any other deferred phase.
