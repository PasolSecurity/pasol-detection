# Test evidence

## 2026-08-03 — Windows validation
### Requirement verified
Parser and detection workspace build/test quality.
### Commit tested
Prior to `fe225e4`, with repository clean.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all -- --check`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo build --workspace --release`.
### Results
Parser 10 tests passed; detection tests passed; Clippy and release builds passed.
### Expected result
Exit code 0.
### Actual result
Exit code 0; Windows incremental cleanup warnings only.
### Artifacts or fixtures
Real PE parser report and PE32/PE64 fixtures.
### Conclusion
Build and baseline runtime behavior verified.

## 2026-08-03 — Workspace after CLI integration
### Requirement verified
Repository-wide regression safety after adding CLI integration tests and golden candidates.
### Commit tested
`772eec6`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
Clippy passed; all workspace tests passed, including 2 CLI integration tests, 4 rule tests, feature/state tests, scoring tests, and doc tests.
### Expected result
Exit code 0.
### Actual result
Exit code 0; incremental-directory cleanup warnings only.
### Artifacts or fixtures
`crates/pasol-lab/tests/cli.rs`, `fixtures/golden/rules/`.
### Conclusion
Repository-wide quality gate passed; golden schema/byte-comparison and operator matrix remain open.
Build and baseline runtime behavior verified.

## 2026-08-03 — Feature schema runtime validation
### Requirement verified
Generated feature reports validate against schema `1.0.0`.
### Commit tested
`03d4f93`.
### Environment
Windows; cargo 1.97.1.
### Commands
`cargo test --workspace --all-features`; `pasol-lab features fixtures/pe32-parser-report.json --format json`.
### Results
Feature report emitted and runtime schema validation succeeded.
### Expected result
Exit code 0 and schema-valid JSON.
### Actual result
Exit code 0.
### Artifacts or fixtures
`fixtures/pe32-parser-report.json`, `schemas/feature-report-v1.schema.json`.
### Conclusion
Runtime feature contract verified.

## 2026-08-03 — Signed pack tests
### Requirement verified
Tamper, unknown-key, invalid-signature, unsigned-production, and budget behavior.
### Commit tested
`a251ba2`.
### Environment
Windows; cargo 1.97.1.
### Commands
`cargo test -p pasol-rules`; `cargo clippy -p pasol-rules --all-targets -- -D warnings`.
### Results
4 tests passed; Clippy passed.
### Expected result
All adversarial cases reject or warn as specified.
### Actual result
All passed.
### Artifacts or fixtures
Generated ephemeral Ed25519 keys in tests.
### Conclusion
Library trust chain verified.

## 2026-08-03 — Key store
### Requirement verified
Key generate, trust, list, and revoke CLI smoke behavior.
### Commit tested
`fe225e4`.
### Environment
Windows; cargo 1.97.1.
### Commands
`pasol-lab rules key generate ...`; `pasol-lab rules key trust ...`; `pasol-lab rules key list ...`; `pasol-lab rules key revoke ...`.
### Results
All commands exited 0; active key listed and revocation completed.
### Expected result
No private key enters trusted store.
### Actual result
Public-key hex only appeared in store; private key remained separate.
### Artifacts or fixtures
Ephemeral files under the Windows temp directory.
### Conclusion
Key-store primitives verified; pack sign/verify still pending.

## 2026-08-03 — Pack CLI
### Requirement verified
Pack signing, trusted-store verification, deterministic manifest output, and modified-content rejection.
### Commit tested
`6df45d6`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`pasol-lab rules key generate test-key PRIVATE PUBLIC`; `pasol-lab rules key trust test-key PUBLIC --store STORE`; `pasol-lab rules pack sign rule-packs/pasol-starter.json --key PRIVATE --key-id test-key --output SIGNED --format json`; `pasol-lab rules pack verify SIGNED --store STORE --format json`.
### Results
Signing and verification exited 0; modified pack exited 4 with manifest-mismatch trust error.
### Expected result
Valid pack verifies; changed content is rejected; JSON contains status/key/manifest without local paths or private material.
### Actual result
Valid output: `status=signed` and `status=verified`, key ID `test-key`; tampering rejected; private key was only written to the temporary key file.
### Artifacts or fixtures
`rule-packs/pasol-starter.json`; temporary Windows files outside the repository.
### Conclusion
CLI smoke behavior verified. Automated integration matrix, revoked-key CLI case, and golden reports remain open.

## 2026-08-03 — CLI adversarial integration matrix
### Requirement verified
Actual-binary CLI key generation, trust, signing, verification, tamper rejection, revocation rejection, unknown-store rejection, invalid private-key rejection, unsigned verification rejection, deterministic signed bytes, and private-key non-disclosure.
### Commit tested
`a8ad9db`.
### Environment
Windows; cargo 1.97.1.
### Commands
`cargo test -p pasol-lab --test cli -- --nocapture`; `cargo fmt --all`.
### Results
2 integration tests passed; both run the compiled `pasol-lab` binary and use temporary keys/stores.
### Expected result
Valid flows exit 0; invalid/tampered/revoked/unknown/unsigned flows exit 4; private material is absent from output; repeated signing is byte-identical.
### Actual result
All assertions passed. Windows incremental cleanup warnings only.
### Artifacts or fixtures
`crates/pasol-lab/tests/cli.rs`, `fixtures/golden/rules/*.json`.
### Conclusion
CLI adversarial matrix is automated. Golden files are checked in but still require schema-validation and generated byte comparison tests.
