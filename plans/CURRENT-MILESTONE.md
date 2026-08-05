# Current Milestone

## Milestone
Phase I — Bounded Pattern Matching (I1 contracts and schemas)

## Objective
Stabilize the public pattern evidence contracts before signing, compilation, worker, or CLI implementation.

## Approved scope
- I0 compatibility is accepted.
- I1 contracts, schemas, runtime validation, deterministic normalization, and bounded evidence are active.

## Explicit non-goals
Do not begin I2+ production functionality, Phase K, or Phase L. Do not add signing, worker execution, CLI commands, file scanning, uploads, enforcement, verdicts, blocking, quarantine, or deletion.

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
`crates/pasol-patterns/`, `schemas/pattern-*.schema.json`, `.github/workflows/msrv.yml`, and `plans/`.

## Tests required
Rust 1.91 workspace and compatibility checks, contract tests, schema validation, deterministic serialization, formatting, workspace tests, and Clippy with warnings denied.

## Security checks required
No signing, worker execution, file scanning, uploads, credentials, verdicts, or enforcement.

## Documentation required
Record I1 contract semantics, schema versions, bounds, MSRV result, and next exact action.

## Acceptance gate
Do not begin I2 until I1 schemas and generated outputs validate deterministically with evidence.

## Current status
Phase G, Phase H, and Phase J are accepted. I0 and I1 are accepted at the contract-foundation level. Phases K and L remain open and unimplemented.

## Next exact action
Activate I2 signed pattern-pack validation in planning before changing implementation code.
