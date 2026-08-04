# Current Milestone

## Milestone
Phase J — Offline Reputation Foundation (J1–J6)

## Objective
Implement the complete offline reputation foundation: contracts, local provider, persistent store, bounded cache semantics, CLI, goldens, documentation, and acceptance evidence.

## Approved scope
- Complete J1 contracts and schemas.
- Complete J2 offline local provider.
- Complete J3 persistent store and atomic updates.
- Complete J4 cache and expiration semantics.
- Complete J5 CLI and integration tests.
- Complete J6 goldens, CI, documentation, and acceptance evidence.

## Explicit non-goals
Do not add remote providers, network access, uploads, enforcement, Phase I pattern work, Phase K parsers, or ML work. Do not change accepted G/H behavior.

## Dependencies
Accepted G/H implementation, SDK types, and schema-validation helpers.

## Tasks
- [x] Close Phase G acceptance evidence.
- [x] Close Phase H acceptance evidence.
- [x] Approve Phase J offline reputation foundation.
- [x] Implement J1 contracts and schemas.
- [x] Implement J2 offline local provider and J3 persistent store.
- [x] Implement J4 cache semantics.
- [ ] Implement J5 complete CLI integration matrix.
- [ ] Implement J6 goldens, CI, documentation, and acceptance evidence.

## Files expected to change
`crates/pasol-reputation/`, `crates/pasol-lab/`, schemas, fixtures, docs, tests, and `plans/`.

## Tests required
Formatting, Clippy warnings denied, workspace tests, schema/golden tests, provider/store/cache tests, CLI integration tests, and documentation tests.

## Security checks required
Offline-only; no network calls, uploads, credentials, verdicts, or enforcement. Unknown and unavailable must remain distinct.

## Documentation required
Document provider semantics, schema compatibility, store safety, cache behavior, privacy, and threat model.

## Acceptance gate
Do not mark H accepted until all mandatory H checklist items have evidence.

## Current status
Phase G and Phase H are accepted at the Stage 2 foundation level. J1–J4 core behavior and the first actual-binary J5 matrix are verified. Final J5/J6 evidence remains open. Phase I remains deferred.

## Next exact action
Reconcile the Phase J acceptance checklist, risks, deferred work, and final evidence without marking scheduled fuzzing or CI execution complete.
