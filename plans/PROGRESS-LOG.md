# Progress log

## 2026-08-03 — Detection foundation
### Planned work
Create the initial feature, rules, and heuristic-score foundation.
### Work completed
Detection SDK, PE feature extraction, starter rules, advisory score, CLI, schemas, and docs.
### Files changed
Workspace crates, schemas, docs, rule pack.
### Tests run
Workspace tests, format, Clippy, release build, real PE smoke test.
### Results
Passed; Windows incremental cleanup warnings recorded.
### Commit
`00b24b8`, `021e028`.
### Checklist changes
G/H/L foundations marked in progress or verified only where evidence existed.
### Known limitations
No patterns, reputation, additional parsers, ML, or signed distribution.
### Remaining work
Continue G/H acceptance evidence.
### Next exact action
H trust hardening.

## 2026-08-03 — Feature states and rule bounds
### Planned work
Separate all feature states and bound rule expressions.
### Work completed
Six-state serialization tests, PE fixtures, expression depth and operator limits.
### Files changed
SDK, features, rules, fixtures.
### Tests run
Workspace tests and Clippy with warnings denied.
### Results
Passed.
### Commit
`588b349`.
### Checklist changes
State semantics and bounds verified.
### Known limitations
Golden output and complete matrix pending.
### Remaining work
Runtime schemas and trust tests.
### Next exact action
Add runtime schema and signature verification.

## 2026-08-03 — Runtime schemas and trust foundation
### Planned work
Validate feature/rule reports and add Ed25519 trust structures.
### Work completed
Runtime schema validation, signed pack verification, resource budgets.
### Files changed
SDK, rules, lab, schemas.
### Tests run
Workspace tests, Clippy, PE32 runtime validation.
### Results
Passed.
### Commit
`03d4f93`, `66b4e42`.
### Checklist changes
Runtime schema and budget items verified.
### Known limitations
No operational pack sign/verify CLI.
### Remaining work
Adversarial trust tests and key store.
### Next exact action
Generated-key tamper tests.

## 2026-08-03 — Adversarial trust and key store
### Planned work
Prove tamper rejection and add operational trusted-key primitives.
### Work completed
Generated-key tests, tamper cases, key store, key-management CLI.
### Files changed
Rules, lab, trust documentation.
### Tests run
Rule tests, Clippy, key generate/trust/list/revoke smoke tests.
### Results
Passed.
### Commit
`a251ba2`, `fe225e4`.
### Checklist changes
Cryptographic test and key-store items verified.
### Known limitations
Pack sign/verify CLI and golden reports pending.
### Remaining work
Final G/H acceptance slice.
### Next exact action
Implement pack sign and verify CLI.
