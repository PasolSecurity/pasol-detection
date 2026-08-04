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
- [~] J2 offline local provider.
- [~] J3 persistent store.
- [ ] J4 cache and expiration semantics.
- [ ] J5 CLI and integration tests.
- [ ] J6 goldens, CI, documentation, and acceptance.
## Test checklist
- [ ] Offline, conflict, expiry, failure, schema tests.
## Documentation checklist
- [ ] Provider and privacy docs.
## Acceptance criteria
All provider and offline tests pass.
## Current status
J1 verified; J2/J3 foundational local lookup and atomic persistence are in progress. No network or remote-provider implementation exists.
## Completed commits
None.
## Remaining work
Complete J1 contracts and schemas, then obtain the next-slice approval for J2.
