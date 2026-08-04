# Current Milestone

## Milestone
Phase I — Bounded Pattern Matching (I0 compatibility and engine decision)

## Objective
Preserve the accepted G/H/J foundation while selecting the next Stage 2 milestone explicitly.

## Approved scope
- G, H, and J acceptance evidence is complete and recorded.
- I0 compatibility and engine-policy evidence is the only active scope.

## Explicit non-goals
Do not begin I1+ production functionality, Phase K, or Phase L work in this planning slice. Do not add execution, uploads, enforcement, verdicts, blocking, quarantine, or deletion.

## Dependencies
Accepted G/H implementation and accepted offline J foundation.

## Tasks
- [x] Close Phase G acceptance evidence.
- [x] Close Phase H acceptance evidence.
- [x] Complete J1–J8 offline reputation foundation and hosted evidence.
- [x] Select and activate Phase I explicitly.
- [~] Complete I0 YARA-X compatibility, ADR, and harmless in-memory test.

## Files expected to change
`plans/`, `docs/adr/ADR-PATTERN-ENGINE.md`, workspace manifests, lockfile, and the temporary compatibility test.

## Tests required
Rust 1.91 compatibility/build check, Windows build, harmless in-memory compile/scan, formatting, workspace tests, and Clippy with warnings denied.

## Security checks required
No secrets, private keys, credentials, or restricted dataset paths in planning files.

## Documentation required
Record YARA-X version, license, feature/module allowlist, MSRV result, and next exact action in the planning files.

## Acceptance gate
Do not begin a new phase until its milestone file, checklist, dependencies, and next exact action are recorded.

## Current status
Phase G, Phase H, and Phase J are accepted at the Stage 2 foundation level. Phase I is active for I0 only. Phases K and L remain open and unimplemented.

## Next exact action
Add the pinned YARA-X compatibility dependency and one harmless in-memory compile-and-scan test, then run the I0 quality gate.
