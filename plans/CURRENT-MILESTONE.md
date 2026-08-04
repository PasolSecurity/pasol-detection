# Current Milestone

## Milestone
Phase J1 — Reputation Contracts and Schemas

## Objective
Define the provider-independent reputation contract and versioned schemas while preserving the accepted G/H baseline.

## Approved scope
- Add stable reputation states and provider descriptors.
- Add reputation report and local-store schema definitions.
- Add runtime validation and deterministic serialization tests.

## Explicit non-goals
Do not add remote providers, network access, uploads, enforcement, Phase I pattern work, Phase K parsers, or ML work. Do not change accepted G/H behavior.

## Dependencies
Accepted G/H implementation, SDK types, and schema-validation helpers.

## Tasks
- [x] Close Phase G acceptance evidence.
- [x] Close Phase H acceptance evidence.
- [x] Approve Phase J offline reputation foundation.
- [~] Implement J1 contracts and schemas.

## Files expected to change
`crates/pasol-reputation/`, `crates/pasol-detection-sdk/`, `schemas/`, tests, docs, and `plans/`.

## Tests required
Formatting, Clippy warnings denied, workspace tests, schema tests, serialization round trips, and documentation tests.

## Security checks required
Offline-only; no network calls, uploads, credentials, verdicts, or enforcement. Unknown and unavailable must remain distinct.

## Documentation required
Document provider semantics, schema compatibility, and offline privacy behavior.

## Acceptance gate
Do not mark H accepted until all mandatory H checklist items have evidence.

## Current status
Phase G and Phase H are accepted at the Stage 2 foundation level. Phase J1 is active. Phase I remains deferred.

## Next exact action
Define the Phase J reputation types and schema, including provider states, provenance, timestamps, cache metadata, and strict separation between unknown, unavailable, and known-benign results.
