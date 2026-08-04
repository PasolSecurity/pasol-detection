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
- [ ] J4 cache and expiration semantics.
- [ ] J5 CLI and integration tests.
- [ ] J6 goldens, CI, documentation, and acceptance.
## Test checklist
- [x] Offline, conflict, expiry, schema, import/export, and CLI tests.
## Documentation checklist
- [ ] Provider and privacy docs.
## Acceptance criteria
All provider and offline tests pass.
## Current status
J1–J3 are verified at the core level; J4 cache semantics and final J5/J6 evidence remain. No network or remote-provider implementation exists.
## Completed commits
None.
## Remaining work
Implement J4 provider-scoped persistent cache and deterministic expiration tests.
