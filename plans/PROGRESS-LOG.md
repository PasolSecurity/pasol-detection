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

## 2026-08-03 — Pack signing and verification CLI
### Planned work
Implement the exact current-milestone pack sign/verify commands using the existing trust store.
### Work completed
Added schema-validated signing, deterministic SHA-256 manifest generation, atomic signed-output write, post-write verification, trusted-store verification, and JSON/human output.
### Files changed
`crates/pasol-rules/src/lib.rs`, `crates/pasol-lab/src/main.rs`.
### Tests run
Formatting; `cargo test -p pasol-lab -p pasol-rules`; Clippy with warnings denied; Windows key-generation, trust, sign, verify, and tamper smoke commands.
### Results
Tests and Clippy passed; sign and verify exited 0; modified pack exited 4 with trust failure.
### Commit
`6df45d6`.
### Checklist changes
Pack CLI marked complete; automated integration and golden evidence remain in progress.
### Known limitations
No pack-sign/verify automated CLI test harness yet; revoked-key and invalid-private-key CLI cases remain open.
### Remaining work
Generated-key CLI integration matrix and golden rule reports.
### Next exact action
Add generated-key CLI integration tests and deterministic golden rule reports.

## 2026-08-03 — CLI adversarial integration tests
### Planned work
Automate the generated-key CLI matrix and add deterministic rule-report fixtures.
### Work completed
Added actual-binary integration tests for valid, tampered, revoked, unknown, invalid-private-key, unsigned, leakage, and deterministic-output cases; checked in four rule-report golden candidates.
### Files changed
`crates/pasol-lab/tests/cli.rs`, `fixtures/golden/rules/`.
### Tests run
`cargo test -p pasol-lab --test cli -- --nocapture`; `cargo fmt --all`.
### Results
2 tests passed; expected exit codes and output assertions passed.
### Commit
`a8ad9db`.
### Checklist changes
Automated CLI matrix complete; golden evidence remains in progress.
### Known limitations
Golden schema validation and operator/state matrix are not yet implemented.
### Remaining work
Validate golden reports and add operator/state tests.
### Next exact action
Add the operator/state matrix tests and validate each golden rule report against the rule-report schema.

## 2026-08-03 — Workspace regression gate
### Planned work
Run the complete workspace quality gate after CLI integration tests.
### Work completed
Ran formatting, Clippy with warnings denied, and all workspace tests.
### Files changed
Planning evidence only.
### Tests run
`cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
All passed; 2 CLI integration tests, 4 rule tests, feature/state/scoring tests, and doc tests passed. Windows incremental cleanup warnings only.
### Commit
`772eec6`.
### Checklist changes
Workspace regression evidence recorded; G/H golden and operator items remain open.
### Known limitations
Golden schema/byte comparison and operator/state matrix are not yet implemented.
### Remaining work
Validate goldens and complete operator matrix.
### Next exact action
Add the operator/state matrix tests and validate each golden rule report against the rule-report schema.
