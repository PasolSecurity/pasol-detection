# Current Milestone

## Milestone
Phase G acceptance closure: deterministic feature goldens and catalog coverage.

## Objective
Close the remaining Phase G evidence gaps without beginning Phase I or changing the accepted H scope.

## Approved scope
- Generate checked-in PE32, PE64, and partial feature-report goldens.
- Compare regenerated feature reports byte-for-byte after schema validation.
- Add catalog-driven positive, negative, unavailable, and truncated coverage.
- Record final G acceptance evidence.

## Explicit non-goals
Do not start I, J, K, or ML. Do not change accepted H behavior, commit private keys, or add enforcement.

## Dependencies
Existing PE parser fixtures, feature schema, `PeFeatureExtractor`, and feature validation helpers.

## Tasks
- [x] Generate PE32, PE64, and partial feature goldens.
- [x] Add byte-for-byte golden regeneration tests.
- [x] Add catalog-driven feature state/value coverage.
- [x] Update G acceptance evidence and formal status.

## Files expected to change
`fixtures/golden/features/`, `crates/pasol-lab/tests/`, feature tests, docs, and `plans/`.

## Tests required
Formatting, feature extraction tests, schema validation, byte-for-byte golden comparison, state coverage, and Clippy warnings denied.

## Security checks required
No local paths or timestamps in normalized reports; preserve unknown, truncated, and unsupported semantics; do not add enforcement.

## Documentation required
Feature catalog coverage and acceptance evidence updates.

## Acceptance gate
Do not mark H accepted until all mandatory H checklist items have evidence.

## Current status
Phase H and Phase G are accepted at the Stage 2 foundation level. Goldens, schema validation, deterministic regeneration, and catalog-driven state coverage are verified.

## Next exact action
Keep Phase I deferred; any future work must begin with a new approved milestone after reviewing the remaining Stage 2 scope.
