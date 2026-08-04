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
Versioned reputation report, local-store, cache, and CLI-error schemas.
## Security requirements
No uploads by default; unknown/unavailable remain distinct; secrets redacted; no verdict or enforcement behavior.
## Implementation checklist
- [x] J1 provider contract, descriptors, states, report types, and runtime schemas.
- [x] J2 offline local provider.
- [x] J3 persistent store.
- [x] J4 cache and expiration semantics.
- [x] J5 CLI and integration tests, including typed exit classes and schema-valid JSON errors. Evidence: `../TEST-EVIDENCE.md#2026-08-04-typed-reputation-cli-errors`; Commit `210eeff`.
- [x] J6 deterministic goldens and schema-drift CI. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-goldens-and-schema-drift-gate`; Commit `1253639`.
- [x] J7 bounded property tests, seven fuzz targets, fourteen-seed replay, and seven hosted smoke campaigns. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-property-invariants`, `../TEST-EVIDENCE.md#2026-08-04-reputation-fuzz-target-compilation`, `../TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`.
- [x] J8 provider, store, privacy, threat-model documentation, and final acceptance evidence. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-documentation-closure`, `../TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`.
## Test checklist
- [x] Offline, conflict, expiry, schema, import/export, and actual-binary CLI tests.
- [x] Typed JSON-error and exit-class matrix.
- [x] Hosted compile/replay and bounded smoke campaigns.
## Documentation checklist
- [x] Provider, store, privacy, and threat-model docs. Evidence: `../TEST-EVIDENCE.md#2026-08-04-reputation-documentation-closure`; Commit `14d9849`.
## Acceptance criteria
All provider, offline, schema, property, fuzz, and hosted workflow tests pass; no network, upload, verdict, or enforcement behavior exists.
## Current status
Phase J is accepted at the offline foundation level. No network or remote-provider implementation exists. Windows sanitizer execution remains a documented limitation mitigated by hosted Ubuntu execution.
## Completed commits
`6c9f199`, `3574c22`, `035c087`, `210eeff`, `1253639`, `31e24f1`, `d770c90`, `585b0cf`, `f983b1c`, `a6d54ee`, `5565e13`, `0c409c7`.
## Remaining work
Select and record the next milestone explicitly before beginning Phase I or any other deferred phase.
