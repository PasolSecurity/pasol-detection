# Current Milestone

## Milestone
No active implementation milestone

## Objective
Preserve the accepted I0–I2 pattern foundation; I3 planning is complete but implementation is inactive.

## Approved scope
- I0 accepted.
- I1 accepted.
- I2 accepted.
- Planning reconciliation only.
- I3 planning specification complete; implementation not authorized.

## Explicit non-goals
Do not begin I3+ production functionality, Phase K, or Phase L. Do not add YARA-X compilation, worker execution, CLI commands, file scanning, uploads, enforcement, verdicts, blocking, quarantine, deletion, or other enforcement behavior.

## Dependencies
Accepted G/H/J foundation and accepted I0, I1, and I2 pattern foundation.

## Tasks
- [x] Close Phase G acceptance evidence.
- [x] Close Phase H acceptance evidence.
- [x] Complete J1–J8 offline reputation foundation and hosted evidence.
- [x] Select and activate Phase I explicitly.
- [x] Complete I0 YARA-X compatibility, ADR, and harmless in-memory test.
- [x] Complete I1 contracts, schemas, runtime validation, deterministic serialization, proof-boundary checks, and golden corpus.
- [x] Complete I2 signed pattern-pack validation, trust verification, hosted replay, and bounded smoke evidence.
- [ ] Planning-only I3 activation.

## Files expected to change
`plans/` only until I3 is explicitly activated.

## Tests required
No implementation tests are authorized in this planning-only state. Preserve the recorded Rust 1.91, workspace, schema, hosted contract, replay, and smoke evidence for I0–I2.

## Security checks required
Do not introduce YARA-X compilation, worker execution, scanning, uploads, credentials, verdicts, blocking, quarantine, deletion, or enforcement.

## Documentation required
Record the accepted I2 evidence and the complete I3 planning specification.

## Acceptance gate
Do not begin I3 until its limits, module policy, warning policy, tests, and non-goals are recorded.

## Current status
No active implementation milestone. I0, I1, and I2 are accepted at the current foundation scope. I3 is ready only for planning-only activation; K and L remain inactive.

## Next exact action
Explicitly approve I3 implementation, then make I3 the sole active milestone before modifying Rust code, schemas, tests, fixtures, CI, or non-planning documentation.
