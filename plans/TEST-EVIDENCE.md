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

## 2026-08-04 — Reputation store and CLI hardening
### Requirement verified
Injected clock, typed SHA-256/provider contract, bounded validated store input, atomic reopen-and-validate writes, transactional reject-duplicate import, deterministic export, and actual-binary reputation CLI coverage.
### Commit tested
`6c9f199`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo test -p pasol-reputation --all-features`; `cargo test -p pasol-lab --test reputation_cli`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
All passed. Three reputation unit tests and two actual-binary CLI tests passed; no network or upload behavior exists.
### Expected result
Expired entries are ignored under a fixed clock, conflicts remain suspicious, import failures preserve original bytes, exports are deterministic, and invalid CLI input exits 4.
### Actual result
All assertions passed on Windows. Incremental-directory Access Denied cleanup warnings remain non-fatal.
### Artifacts or fixtures
`crates/pasol-reputation/src/lib.rs`, `crates/pasol-lab/tests/reputation_cli.rs`, import/export CLI commands, and updated store schema.
### Conclusion
J1–J3 core behavior and the first J5 integration matrix are verified; J4 cache and J6 acceptance evidence remain open.

## 2026-08-04 — Persistent reputation cache
### Requirement verified
Provider/version/query/hash cache keys, injected-clock expiration, state-specific TTLs, source-revision invalidation, bounded deterministic eviction, atomic persistence, runtime schema validation, corruption rejection, and CLI cache-hit behavior.
### Commit tested
`035c087`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo test -p pasol-reputation --all-features`; `cargo test -p pasol-lab --test reputation_cli`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Five reputation unit tests and two actual-binary CLI tests passed; Clippy passed.
### Expected result
Cache hits require matching provider/version/query/hash/source revision; expired and invalidated entries miss; temporary states never become benign.
### Actual result
All assertions passed. Cache reports `hit=false` on fresh provider results and `hit=true` on repeated cached lookup.
### Artifacts or fixtures
`schemas/reputation-cache-1.0.0.schema.json`, `ReputationCache`, `CachePolicy`, CLI `--cache` option.
### Conclusion
J4 cache core is verified; typed exits, goldens, schema-drift CI, property/fuzz tests, and final J6 evidence remain.

## 2026-08-04 — Typed reputation CLI errors
### Requirement verified
Reputation CLI failures now use stable exit classes and a versioned JSON error envelope when `--format json` is requested. Error output is emitted on stderr, success output remains on stdout, and normalized messages do not expose local paths.
### Commit tested
`210eeff`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo test -p pasol-lab --test reputation_cli -p pasol-reputation`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Two actual-binary reputation CLI tests and all reputation unit tests passed; Clippy passed with warnings denied.
### Expected result
Invalid input exits 4, missing files exit 3, corrupt store/cache errors exit 4, JSON errors validate against `reputation-cli-error-1.0.0.schema.json`, and stdout remains empty on failure.
### Actual result
All assertions passed on Windows. Invalid hash, corrupt store, missing store, and corrupt cache produced schema-valid JSON errors on stderr with the expected exit classes. Existing unknown lookup and cache-hit success paths remained exit 0.
### Artifacts or fixtures
`schemas/reputation-cli-error-1.0.0.schema.json`, `validate_cli_error_json`, `crates/pasol-lab/tests/reputation_cli.rs`.
### Conclusion
The typed CLI error slice is verified. Reputation goldens, schema-drift extension, property/fuzz coverage, and final J6 acceptance remain open.

## 2026-08-04 — Workspace regression after typed errors
### Requirement verified
The typed error implementation does not regress accepted G/H behavior or existing J1–J4 reputation behavior.
### Commit tested
`210eeff`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo test --workspace --all-features`.
### Results
All workspace unit, integration, schema, feature, rule, reputation, scoring, and documentation tests passed.
### Expected result
Workspace tests pass with exit code 0 and no functional regressions.
### Actual result
Exit code 0; all listed tests passed. Windows incremental cleanup warnings were non-fatal.
### Artifacts or fixtures
Workspace test binaries and checked-in schemas/goldens.
### Conclusion
The typed CLI error slice is compatible with the current workspace; J5/J6 acceptance work remains open.

## 2026-08-04 — Reputation goldens and schema-drift gate
### Requirement verified
FixedClock-generated reputation reports and CLI-error envelopes are checked in as deterministic goldens. Reports and errors validate against their runtime schemas, and regeneration compares serialized bytes exactly. The schema-drift workflow now runs the golden test on Ubuntu and Windows runners.
### Commit tested
`1253639`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo test -p pasol-reputation --test goldens`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
Four golden tests passed, Clippy passed with warnings denied, and the full workspace suite passed with 27 executable tests and all documentation tests.
### Expected result
Known-benign, known-malicious, suspicious, unknown, expired-as-unknown, cache-hit, cache-miss, and five CLI-error goldens are schema-valid, byte-stable, ordered deterministically, and path-free.
### Actual result
All goldens regenerated byte-for-byte under the FixedClock. No local paths or temporary filenames appear. The workflow includes Ubuntu and Windows matrix runners and the reputation golden test.
### Artifacts or fixtures
`fixtures/golden/reputation/`, `crates/pasol-reputation/tests/goldens.rs`, `.github/workflows/schema-drift.yml`.
### Conclusion
The deterministic golden slice is verified. Property tests, fuzz targets, provider/privacy documentation, and final J6 acceptance evidence remain open.

## 2026-08-04 — Reputation property invariants
### Requirement verified
Bounded property tests cover lowercase SHA-256 round trips, store serialization semantics, cache-key separation, order-independent lookup, conflict resolution, source-revision invalidation, and expiry misses.
### Commit tested
`31e24f1`.
### Environment
Windows; rustc/cargo 1.97.1.
### Commands
`cargo fmt --all`; `cargo test -p pasol-reputation --test properties --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Five property/invariant tests passed, including generated cases from `proptest`; Clippy passed with warnings denied.
### Expected result
Generated valid hashes preserve lowercase spelling, serialized stores preserve records, cache keys separate by hash, conflicts resolve to suspicious, and changed revisions or expired entries never produce a current cache hit.
### Actual result
All generated cases and deterministic invariants passed on Windows. No network, uploads, or enforcement behavior were introduced.
### Artifacts or fixtures
`crates/pasol-reputation/tests/properties.rs`, workspace `proptest` dependency.
### Conclusion
The J7 property-test slice is verified. Fuzz targets, documentation, and final J8 acceptance remain open.

## 2026-08-04 — Reputation fuzz-target compilation
### Requirement verified
Seven bounded in-memory fuzz targets were added for report, local-store, cache, import, conflict, expiration, and store/cache round-trip paths. Inputs are capped at 1 MiB and serialized outputs at 4 MiB; no target performs network access or file writes.
### Commit tested
`d770c90`, with build-artifact cleanup in `585b0cf`.
### Environment
Windows; rustc/cargo 1.97.1. `cargo-fuzz` was not installed locally.
### Commands
`cargo fmt --manifest-path fuzz/Cargo.toml --all`; `cargo check --manifest-path fuzz/Cargo.toml --bins`.
### Results
All seven fuzz binaries compiled successfully with exit code 0 after one compile fix. The generated `fuzz/target` directory is ignored and not tracked.
### Expected result
Every target compiles, remains bounded, and exercises production validators without network, uploads, or unrestricted filesystem operations.
### Actual result
Seven targets compiled successfully. A native `cargo fuzz build` and scheduled campaign were not run because `cargo-fuzz` is unavailable in this Windows environment.
### Artifacts or fixtures
`fuzz/Cargo.toml`, `fuzz/fuzz_targets/`, `fuzz/.gitignore`, schema-drift compile step.
### Conclusion
Fuzz targets are implemented and compile-verified. Scheduled fuzzing, regression corpora, documentation, and final J8 acceptance remain open.

## 2026-08-04 — Reputation documentation closure
### Requirement verified
Provider semantics, store safety, privacy behavior, cache invalidation, CLI exit classes, import rollback, limits, corruption recovery, and the Phase J threat model are documented.
### Commit tested
`14d9849`.
### Environment
Windows; repository inspection after documentation update.
### Commands
Documentation review of `docs/REPUTATION-PROVIDERS.md`, `docs/LOCAL-REPUTATION-STORE.md`, `docs/REPUTATION-PRIVACY.md`, and `docs/REPUTATION-THREAT-MODEL.md`.
### Results
All required Phase J documentation topics are present; no code behavior was changed in this slice.
### Expected result
Documentation distinguishes all states, unknown from benign, conflict and expiration behavior, bounds, atomic persistence, privacy, typed errors, and non-enforcement scope.
### Actual result
The reviewed documents contain the required semantics and retain Windows ACL hardening as an open limitation.
### Artifacts or fixtures
The four reputation documentation files listed above.
### Conclusion
Documentation closure is verified. Scheduled fuzzing, regression corpus, and final acceptance reconciliation remain open.

## 2026-08-04 — Hosted fuzz workflow and regression corpus
### Requirement verified
A dedicated least-privilege workflow now separates pull-request compile/corpus replay from scheduled smoke campaigns. Seven corpus directories contain 14 deterministic harmless seeds covering valid, invalid, conflict, expiration, and corrupt inputs.
### Commit tested
`f983b1c`.
### Environment
Windows repository inspection; hosted workflow not executed in this local environment.
### Commands
Corpus inventory and workflow review; local `cargo check --manifest-path fuzz/Cargo.toml --bins` remains the available compile evidence.
### Results
The workflow is structurally configured with pinned checkout/upload actions, `cargo fuzz build`, bounded corpus replay, 15-second scheduled campaigns, safe failure-artifact upload, and read-only contents permissions.
### Expected result
Pull requests compile and replay every target corpus; scheduled runs execute bounded smoke campaigns and preserve only failure artifacts.
### Actual result
Workflow and corpus are checked in. No hosted run link, crash count, timeout count, or campaign result is claimed yet.
### Artifacts or fixtures
`.github/workflows/reputation-fuzz.yml`, `fuzz/corpus/`, 14 seed files across seven targets.
### Conclusion
Hosted fuzz infrastructure and initial corpus are implemented. Hosted execution, regression replay evidence, and final acceptance remain open.

## 2026-08-04 — Local cargo-fuzz feasibility check
### Requirement verified
The corrected cargo-fuzz manifest metadata and libFuzzer argument forwarding were tested locally. The fuzz package builds with nightly Rust, but Windows execution is unavailable with the installed MSVC toolchain.
### Commit tested
Working tree after `6c80194`; implementation correction pending commit.
### Environment
Windows MSVC; Rust stable 1.97.1 and nightly 1.99.0-nightly; cargo-fuzz 0.13.2.
### Commands
`cargo install cargo-fuzz --locked`; `RUSTUP_TOOLCHAIN=nightly cargo fuzz build`; `RUSTUP_TOOLCHAIN=nightly cargo fuzz run reputation_report fuzz/corpus/reputation_report -- -runs=20`.
### Results
Cargo-fuzz installed successfully and all seven targets compiled under nightly. The first execution failed at MSVC link time with unresolved sanitizer-coverage symbols and exit code `0xc0000135`/LNK1120.
### Expected result
Local smoke execution should run the corpus without crashes or invariant failures.
### Actual result
Compilation succeeded; Windows execution could not start because the MSVC sanitizer runtime symbols are unavailable. No product crash or invariant failure was observed.
### Artifacts or fixtures
Fuzz package metadata, workflow argument forwarding, and local toolchain installation.
### Conclusion
Hosted Linux execution remains required for campaign evidence. Phase J is not accepted.

### Additional workspace verification
`cargo test --workspace --all-features` passed after commit `035c087`; 25 tests and all doc tests completed successfully. Windows incremental cleanup warnings remained non-fatal.
## 2026-08-04 — Hosted fuzz workflow run 30930784059
### Requirement verified
Hosted Phase J fuzz workflow execution.
### Commit tested
e816fddd4b87adf00da0aa52689790c10eeb96da
### Environment
GitHub Actions Ubuntu 24.04.4, runner 2.336.0, cargo-fuzz 0.13.2.
### Commands
`cargo install cargo-fuzz --locked`; `cargo fuzz build`.
### Results
Workflow dispatched successfully, but `scheduled-smoke` failed before target compilation.
### Expected result
Nightly Rust selected and seven targets compile.
### Actual result
Stable Rust was selected; cargo-fuzz passed nightly-only `-Zsanitizer` flags and rustc exited 1. Compile/replay job was skipped for manual dispatch.
### Artifacts or fixtures
Workflow run: https://github.com/PasolSecurity/pasol-detection/actions/runs/30930784059
### Conclusion
Hosted acceptance remains open. Workflow corrected to install/select nightly before rerun.

## 2026-08-04 — Windows workspace regression validation
### Requirement verified
Detection workspace tests and formatting after hosted workflow correction.
### Commit tested
Working tree before workflow-fix commit.
### Environment
Windows PowerShell, Rust stable toolchain.
### Commands
`cargo fmt --check`; `cargo test --workspace --all-features`
### Results
Formatting passed; all workspace tests passed.
### Expected result
No regression in G/H/J behavior.
### Actual result
All tests passed, including the complete workspace test groups.
### Artifacts or fixtures
Feature/rule/reputation goldens and schemas under `fixtures/golden/` and `schemas/`.
### Conclusion
Local regression gate passed; hosted fuzz execution is still pending.
## 2026-08-04 — Hosted fuzz smoke run 30931071619
### Requirement verified
Hosted nightly fuzz compilation and bounded smoke campaigns.
### Commit tested
a6d54ee
### Environment
GitHub Actions Ubuntu 24.04.4, runner 2.336.0, nightly Rust, cargo-fuzz 0.13.2.
### Commands
Workflow `reputation-fuzz` manual dispatch; `cargo fuzz build`; seven `cargo fuzz run` campaigns with `-max_total_time=15`.
### Results
Compile fuzz targets passed; all seven campaigns passed.
### Expected result
No crash, timeout, invariant failure, or memory failure.
### Actual result
Success; no artifacts uploaded, indicating no failure artifacts.
### Artifacts or fixtures
Workflow run: https://github.com/PasolSecurity/pasol-detection/actions/runs/30931071619
### Conclusion
Hosted smoke evidence is green. Compile/replay remained skipped and is being enabled for manual dispatch.

## 2026-08-04 — Hosted fuzz acceptance run
### Requirement verified
Phase J hosted fuzz compilation, deterministic corpus replay, and bounded smoke campaigns.
### Commit tested
`5565e13b41a29d33b208420cf26a481d276e1380`.
### Environment
GitHub Actions Ubuntu 24.04.4, runner 2.336.0, nightly Rust `1.99.0-nightly` (`504869653`, 2026-08-03), cargo-fuzz `0.13.2`.
### Commands
Workflow `reputation-fuzz` manual dispatch: `cargo fuzz build`; each of the seven targets replayed with `-runs=20`; each of the seven smoke campaigns run with `-max_total_time=15`.
### Results
Both workflow jobs completed successfully. Seven fuzz targets compiled, fourteen corpus seeds replayed, and seven bounded campaigns completed. Crash count: 0. Timeout count: 0. Invariant-failure count: 0. No failure artifacts were uploaded.
### Expected result
All targets compile and replay without panic, timeout, invariant failure, or memory failure; smoke campaigns complete successfully.
### Actual result
The expected result was achieved on both compile/replay and scheduled-smoke jobs.
### Artifacts or fixtures
Workflow run: https://github.com/PasolSecurity/pasol-detection/actions/runs/30931536513; corpus under `fuzz/corpus/`.
### Conclusion
Hosted Phase J fuzz execution is verified. Windows sanitizer execution remains unavailable locally and is mitigated by hosted Linux execution.

## 2026-08-04 — Phase I0 YARA-X compatibility spike
### Requirement verified
Pinned YARA-X `1.19.0` resolves with the selected restricted feature set and compiles/scans harmless in-memory bytes on Windows.
### Commit tested
Working tree for the I0 compatibility slice; commit pending.
### Environment
Windows MSVC, Rust `1.97.1`, cargo `1.97.1`; YARA-X `1.19.0` (BSD-3-Clause). Rust `1.91.0` is not installed locally.
### Commands
`cargo test -p pasol-detection-sdk --test yara_x_compat -- --nocapture`; `cargo fmt --check`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `rustup run 1.91.0 rustc --version`.
### Results
The harmless compatibility test passed. Formatting, all workspace tests, and Clippy with warnings denied passed. The MSRV command reported that toolchain `1.91.0-x86_64-pc-windows-msvc` is not installed.
### Expected result
YARA-X builds with the pinned features, the harmless rule matches deterministically, and all local quality checks pass; MSRV is either verified or explicitly recorded as blocked.
### Actual result
Windows compatibility and local quality checks passed. MSRV verification is blocked by the unavailable local toolchain and remains unchecked.
### Artifacts or fixtures
`docs/adr/ADR-PATTERN-ENGINE.md`, `Cargo.toml`, `Cargo.lock`, and `crates/pasol-detection-sdk/tests/yara_x_compat.rs`.
### Conclusion
I0 is partially verified: the dependency and Windows compatibility gate pass, while the Rust 1.91 check requires a CI runner or installed toolchain before I0 acceptance.

## 2026-08-04 — Phase I0 MSRV and I1 contracts
### Requirement verified
Rust 1.91 compatibility and the I1 contract foundation.
### Commit tested
Working tree after `58e20ed`; I1 implementation commit pending.
### Environment
Windows MSVC; rustc/cargo `1.91.0`; YARA-X `1.19.0`; restricted default-disabled feature set with PE, hash, math, and string modules.
### Commands
`rustc +1.91.0 -Vv`; `cargo +1.91.0 -V`; `cargo +1.91.0 check --workspace --all-targets --all-features`; `cargo +1.91.0 test --workspace --all-features`; `cargo +1.91.0 clippy --workspace --all-targets --all-features -- -D warnings`; `cargo +1.91.0 fmt --all -- --check`; `cargo +1.91.0 test -p pasol-detection-sdk --test yara_x_compat -- --nocapture`; `cargo +1.91.0 test -p pasol-patterns --all-features`.
### Results
Rust 1.91 workspace check, tests, Clippy, formatting, and dedicated YARA-X compatibility test passed. I1 contract unit and integration tests passed: eight statuses, deterministic normalization, bounds, path rejection, schema document validation, runtime report validation, and byte-stable serialization. Windows incremental cleanup warnings were non-fatal.
### Expected result
I0 MSRV gate passes and I1 contracts validate deterministically under the declared MSRV.
### Actual result
Expected result achieved.
### Artifacts or fixtures
`crates/pasol-patterns/`, `schemas/pattern-*.schema.json`, `.github/workflows/msrv.yml`.
### Conclusion
I0 is accepted. I1 contract implementation is operational and remains in progress pending broader schema/golden evidence before I1 acceptance.

## 2026-08-04 — I1 contract hardening
### Requirement verified
I1 semantic and schema contract hardening for requests, reports, worker envelopes, payload identity, metadata, limits, statuses, and source paths.
### Commit tested
Working tree after `8f827cf`; hardening commit pending.
### Environment
Windows MSVC, Rust `1.97.1` local focused run; Rust `1.91.0` compatibility was verified in the preceding I0 gate.
### Commands
`cargo fmt`; `cargo test -p pasol-patterns --all-features`.
### Results
Six focused tests passed: three unit tests and three integration tests. Tests cover all eight statuses, deterministic ordering, checked-in schema documents, runtime report validation, payload SHA-256/length binding, typed metadata, source-path checks, and schema-version rejection.
### Expected result
Contract-level validation rejects identity mismatches, unsupported schemas, invalid paths, unbounded metadata, invalid statuses, and output-limit violations.
### Actual result
Expected contract behavior passed. The required checked-in golden corpus is not yet present.
### Artifacts or fixtures
`crates/pasol-patterns/`, `schemas/pattern-*.schema.json`.
### Conclusion
I1 hardening is implemented but remains incomplete until the deterministic golden corpus and negative regeneration tests are checked in and verified.

## 2026-08-04 — Final Windows workspace quality gate
### Requirement verified
No regression in the accepted G/H/J implementation after planning reconciliation.
### Commit tested
Working tree containing the hosted-evidence planning update.
### Environment
Windows PowerShell, Rust stable toolchain.
### Commands
`cargo fmt --check`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Formatting, all workspace tests, and Clippy with warnings denied passed. The workspace test run completed all unit, integration, golden, property, schema, and documentation tests successfully.
### Expected result
Exit code 0 for every command and no warnings denied by Clippy.
### Actual result
All commands exited 0.
### Artifacts or fixtures
Feature, rule, and reputation fixtures/goldens and schemas under `fixtures/` and `schemas/`.
### Conclusion
The local regression gate is green; hosted Linux fuzz execution is recorded separately above.

## 2026-08-04 — I1 proof boundary and golden corpus
### Requirement verified
I1 proof-boundary corrections, source-line-ending policy, twelve deterministic pattern goldens, schema validation, semantic validation, and negative contract coverage.
### Commit tested
`53ad196` locally; published remote `main` verified at `53ad196c9d4033b88441f60bae7f1e74721ca87a`.
### Environment
Windows MSVC, `rustc 1.91.0 (f8297e351 2025-10-28)`, Cargo `1.91.0`, YARA-X `1.19.0` with restricted features.
### Commands
`cargo +1.91.0 check --workspace --all-targets --all-features` (exit 0); `cargo +1.91.0 test --workspace --all-features` (exit 0); `cargo +1.91.0 clippy --workspace --all-targets --all-features -- -D warnings` (exit 0); `cargo +1.91.0 fmt --all -- --check` (exit 0 after formatting); focused contract tests were included in the workspace run.
### Results
Workspace check, 1.91 workspace tests, Clippy with warnings denied, and formatting passed. Pattern contracts: 3 unit tests and 6 integration tests passed. The twelve checked-in pattern goldens validate and round-trip byte-for-byte; source tests accept LF/CRLF/TAB and reject standalone CR, NUL, and prohibited controls.
### Expected result
Untrusted verified-pack construction, payload identity mismatch, unsupported schemas, invalid source paths/controls, invalid status/evidence combinations, and unbounded output are rejected; valid deterministic reports and protocol envelopes validate against schema `1.0.0`.
### Actual result
All expected checks passed. No worker, compiler, signing, CLI, file scanning, upload, verdict, or enforcement behavior was added.
### Artifacts or fixtures
`fixtures/golden/patterns/` contains nine report goldens plus valid scan, worker-request, and worker-response goldens. Schemas are under `schemas/pattern-*.schema.json`.
### Conclusion
I1 contract foundation is accepted. I2 signed pattern-pack validation remains the next planned milestone and is not implemented.

## 2026-08-05 — I2 shared trust extraction
### Requirement verified
Initial I2 shared Ed25519 trust layer with Phase H compatibility re-exports.
### Commit tested
Working tree after `df80c50`; trust extraction commit pending.
### Environment
Windows MSVC, Rust `1.91.0`.
### Commands
`cargo +1.91.0 fmt --all`; `cargo +1.91.0 test -p pasol-trust -p pasol-rules --all-features`; `cargo +1.91.0 clippy -p pasol-trust -p pasol-rules --all-targets --all-features -- -D warnings`.
### Results
Formatting passed; three `pasol-trust` tests and six existing `pasol-rules` tests passed; Clippy passed with warnings denied.
### Expected result
Trust-store schema validation, atomic persistence, active/retired resolution, revoked/unknown/invalid-key rejection, and unchanged Phase H behavior.
### Actual result
Expected result achieved for the extracted library slice. Pattern integration and full workspace gates remain pending.
### Artifacts or fixtures
`crates/pasol-trust/tests/store.rs` and existing rule-pack tests.
### Conclusion
I2.1 trust extraction is locally verified but not yet formally complete until pattern integration and full workspace evidence pass.
