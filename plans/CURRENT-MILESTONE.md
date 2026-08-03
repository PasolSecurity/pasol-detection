# Current Milestone

## Milestone
Final G/H acceptance slice: signing/verification CLI and trusted-key operational workflow.

## Objective
Make the existing Ed25519 trust library usable through deterministic CLI commands while preserving production/development separation.

## Approved scope
- Add `pasol-lab rules pack sign` and `pack verify`.
- Use existing signed-pack structure and trusted-key store.
- Validate schemas before signing/verifying and validate generated reports.
- Add generated-key integration tests and deterministic manifest tests.
- Update trust documentation and planning evidence.

## Explicit non-goals
Do not start I, J, K, or ML. Do not commit private keys or add enforcement.

## Dependencies
Existing rule schemas, Ed25519 library, `TrustedKeyStore`, and current rule CLI.

## Tasks
- [~] Implement pack sign CLI.
- [ ] Implement pack verify CLI against trusted store.
- [ ] Add tamper and deterministic-manifest integration tests.
- [ ] Add golden rule evidence and update acceptance records.

## Files expected to change
`crates/pasol-lab/src/main.rs`, `crates/pasol-rules/src/lib.rs`, schemas, tests, docs, and `plans/`.

## Tests required
Formatting, workspace tests, Clippy warnings denied, schema validation, valid/tampered/wrong-key/unknown-key/unsigned CLI cases, deterministic output inspection.

## Security checks required
No private keys in repository or logs; production verify must require a trusted active key; revoked keys must fail; writes must be atomic.

## Documentation required
Trust lifecycle, CLI usage, rotation/revocation, and evidence updates.

## Acceptance gate
Do not mark H accepted until all mandatory H checklist items have evidence.

## Current status
Trusted-key store and key-management commands exist in `fe225e4`; pack sign/verify commands and golden evidence remain.

## Next exact action
Implement `pasol-lab rules pack sign` and `pasol-lab rules pack verify` using the existing signed-pack format and trusted-key store, then add generated-key CLI integration tests.
