# Current Milestone

## Milestone
Phase I2 — Signed Pattern-Pack Validation

## Objective
Validate signed, bounded, versioned pattern packs and produce proof-carrying verified-pack objects without compiling or scanning rules.

## Approved scope
- I0 compatibility is accepted.
- I1 contracts, schemas, runtime validation, deterministic normalization, and bounded evidence are accepted.
- I2 shared trust, manifest/signature contracts, canonical signing, exact source hashing, bounded verification, tests, CI, and documentation are active.

## Explicit non-goals
Do not begin I3+ production functionality, Phase K, or Phase L. Do not add YARA-X compilation, worker execution, CLI commands, file scanning, uploads, enforcement, verdicts, blocking, quarantine, or deletion.

## Dependencies
Accepted G/H/J foundation and accepted I0 YARA-X compatibility baseline.

## Tasks
- [x] Close Phase G acceptance evidence.
- [x] Close Phase H acceptance evidence.
- [x] Complete J1–J8 offline reputation foundation and hosted evidence.
- [x] Select and activate Phase I explicitly.
- [x] Complete I0 YARA-X compatibility, ADR, and harmless in-memory test.
- [x] Implement I1 pattern contracts, schemas, runtime validation, deterministic serialization, proof-boundary checks, and the twelve-file golden corpus.

## Files expected to change
`crates/pasol-trust/`, `crates/pasol-patterns/`, schemas, tests, fixtures, fuzz targets, CI, documentation, and planning files.

## Tests required
Rust 1.91 workspace and compatibility checks, contract tests, schema validation, deterministic serialization, formatting, workspace tests, and Clippy with warnings denied.

## Security checks required
No signing, worker execution, file scanning, uploads, credentials, verdicts, or enforcement.

## Documentation required
Record I1 contract semantics, schema versions, bounds, MSRV result, and next exact action.

## Acceptance gate
Do not begin I2 until I1 schemas and generated outputs validate deterministically with evidence.

## Current status
Phase G, Phase H, Phase J, I0, and I1 are accepted. I2 implementation, local gates, and hosted Ubuntu/Windows contract verification are complete; final I2 acceptance remains open for hosted fuzz-campaign evidence and checklist reconciliation. Phases K and L remain inactive.

## Next exact action
Add a bounded hosted I2 fuzz-smoke job for the three pattern-pack fuzz targets, record target/corpus/duration/crash/timeout evidence, and then review every remaining I2 checkbox before acceptance.
