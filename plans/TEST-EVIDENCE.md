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

## 2026-08-03 — Golden and operator matrix
### Requirement verified
Supported operator uncertainty semantics and deterministic rule-report goldens.
### Commit tested
`ff39e83`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo test -p pasol-rules`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
Six rule tests passed, including the operator/state matrix and byte-stable/schema-valid golden reports; full workspace tests and Clippy passed.
### Expected result
Unknown, truncated, not-applicable, and unsupported states become `not_evaluated`; missing `exists` is a known non-match; all four golden reports validate and regenerated production serialization matches byte-for-byte (including checked-in newline).
### Actual result
All assertions passed. Windows incremental cleanup warnings only.
### Artifacts or fixtures
`fixtures/golden/rules/{match,no-match,not-evaluated,budget-warning}.json`; `crates/pasol-rules/src/lib.rs` matrix and golden tests.
### Conclusion
Golden rule evidence and operator/state semantics are verified. Schema-drift CI and starter-rule positive/negative fixtures remain.
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

## 2026-08-03 — Schema drift and starter fixtures
### Requirement verified
Checked-in feature/rule schemas and rule goldens validate at runtime; starter rule has positive and negative fixtures.
### Commit tested
`5627210`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo test --workspace --all-features`; `cargo test --workspace schema`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Workspace tests passed; 2 new `pasol-lab` schema tests passed; schema-filtered test passed; Clippy passed with warnings denied.
### Expected result
Schema drift and starter-rule regressions fail deterministically without machine-specific paths.
### Actual result
PE32/PE64 features, rule pack, four rule goldens, and generated reports validated; positive fixture matched and negative fixture did not.
### Artifacts or fixtures
`crates/pasol-lab/tests/schema.rs`, `fixtures/rules/starter-positive-feature.json`, `fixtures/rules/starter-negative-feature.json`, `.github/workflows/schema-drift.yml`.
### Conclusion
This slice is verified in `5627210`.

## 2026-08-03 — Phase J1/J2 foundation
### Requirement verified
Provider-independent reputation states, report/store schemas, runtime validation, deterministic local lookup, expiration filtering, conflict handling, atomic persistence, and offline CLI lookup/add/remove/validate operations.
### Commit tested
`e4df109`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; manual `pasol-lab reputation add/lookup` smoke test.
### Results
Workspace tests and Clippy passed. Known-benign and unknown lookups produced schema-valid reports; no network access or uploads were added.
### Expected result
All reputation states remain distinct and unknown is not benign.
### Actual result
J1 contracts and schemas are verified; J2/J3 local provider/store foundation works offline.
### Artifacts or fixtures
`crates/pasol-reputation/`, `schemas/reputation-report-1.0.0.schema.json`, `schemas/local-reputation-store-1.0.0.schema.json`, reputation CLI, documentation.
### Conclusion
Foundation slice verified; cache semantics, complete integration matrix, goldens, and formal Phase J acceptance remain open.

## 2026-08-03 — Phase H acceptance
### Requirement verified
Phase H deterministic evaluation, signed-pack trust, key lifecycle, bounded evaluation, schema contracts, adversarial CLI tests, starter fixtures, and schema-drift regression are complete at the Stage 2 foundation level.
### Commit tested
`5627210`, with planning evidence in `6fa0e1c`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo test --workspace --all-features`; `cargo test --workspace schema`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
All workspace, schema, and Clippy checks passed; Windows incremental cleanup warnings only.
### Expected result
No mandatory H implementation or verification requirement remains open.
### Actual result
H evidence is complete; Phase I remains unstarted and deferred.
### Artifacts or fixtures
Signed-pack CLI integration tests, rule goldens, starter fixtures, schema-drift workflow, and planning records.
### Conclusion
Phase H is accepted at the Stage 2 foundation level; this is not a final antivirus verdict or enforcement system.

## 2026-08-03 — Phase G feature goldens
### Requirement verified
Deterministic PE32, PE64, and partial feature reports are checked in, schema-valid, and regenerated byte-for-byte from the production extractor. Catalog-driven tests cover the implemented PE feature identifiers, positive/negative baseline behavior, unknown entropy, unsupported imports, and partial/truncated parser status.
### Commit tested
`ffa4442`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all -- --check`; `cargo test -p pasol-lab --test features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
All checks passed; 3 feature tests passed, including three golden comparisons and state coverage. Windows incremental cleanup warnings only.
### Expected result
Golden reports validate against schema 1.0.0, remain deterministic, and contain no machine-specific paths or timestamps.
### Actual result
PE32, PE64, and PE64-partial goldens matched regenerated output byte-for-byte; schema validation passed; unknown, unsupported, and partial states were preserved.
### Artifacts or fixtures
`fixtures/golden/features/pe32.json`, `pe64.json`, `pe64-partial.json`, `fixtures/pe64-partial-parser-report.json`, `crates/pasol-lab/tests/features.rs`.
### Conclusion
Phase G acceptance evidence is complete at the Stage 2 foundation level.
