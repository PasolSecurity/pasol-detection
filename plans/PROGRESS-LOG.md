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

## 2026-08-04 — Local cargo-fuzz feasibility check
### Planned work
Validate the corrected fuzz workflow contract locally before relying on hosted execution.
### Work completed
Installed cargo-fuzz 0.13.2, added cargo-fuzz package metadata and corrected libFuzzer argument forwarding, and compiled all seven targets with nightly Rust.
### Files changed
`fuzz/Cargo.toml`, `.github/workflows/reputation-fuzz.yml`.
### Tests run
`cargo install cargo-fuzz --locked`; `RUSTUP_TOOLCHAIN=nightly cargo fuzz build`; `RUSTUP_TOOLCHAIN=nightly cargo fuzz run reputation_report fuzz/corpus/reputation_report -- -runs=20`.
### Results
Build passed. Windows execution failed at MSVC sanitizer-coverage linking with unresolved `__start___sancov_pcs`/`__stop___sancov_pcs` symbols.
### Commit
Pending implementation correction commit.
### Checklist changes
Hosted execution remains unchecked; Windows build and the blocker are recorded in `TEST-EVIDENCE.md` and `RISKS-AND-BLOCKERS.md`.
### Known limitations
The detection repository is not available through the authenticated GitHub account, so hosted Linux execution cannot yet be triggered.
### Remaining work
Push to an available detection repository or obtain access, run hosted Linux fuzz jobs, and record workflow evidence.
### Next exact action
Resolve repository access, push the current branch, and run the pull-request and manually dispatched fuzz workflows.

## 2026-08-04 — Typed reputation CLI errors
### Planned work
Add stable reputation CLI exit classes and structured JSON errors before beginning reputation goldens and final J6 evidence.
### Work completed
Added the versioned CLI error schema, mapped reputation failures to typed exit classes, emitted structured errors to stderr for JSON mode, and expanded actual-binary tests for invalid hash, corrupt store/cache, and missing-store cases.
### Files changed
`crates/pasol-lab/src/main.rs`, `crates/pasol-lab/tests/reputation_cli.rs`, `crates/pasol-reputation/src/lib.rs`, `schemas/reputation-cli-error-1.0.0.schema.json`.
### Tests run
`cargo fmt --all`; `cargo test -p pasol-lab --test reputation_cli -p pasol-reputation`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
All focused tests passed on Windows; Clippy passed with warnings denied.
### Commit
`210eeff`.
### Checklist changes
J5 typed exit/error behavior is verified in `TEST-EVIDENCE.md`; J5 and J6 remain open pending goldens and broader integration evidence.
### Known limitations
Clap usage errors are still handled by Clap’s native usage path; reputation provider-unavailable and integrity-specific classes have no active provider implementation yet.
### Remaining work
Add deterministic reputation goldens, extend schema-drift CI, add property/fuzz coverage, and complete final Phase J acceptance evidence.
### Next exact action
Add deterministic reputation report/store/cache golden fixtures and byte-for-byte regeneration tests with runtime schema validation.

## 2026-08-04 — Reputation goldens and schema-drift gate
### Planned work
Generate deterministic reputation and CLI-error golden files with FixedClock, validate them at runtime, and extend schema-drift CI to Windows and Linux.
### Work completed
Added `report_at` for deterministic production report generation, FixedClock golden tests for five reputation states plus cache hit/miss, five schema-valid CLI-error goldens, and a schema-drift matrix covering Ubuntu and Windows.
### Files changed
`crates/pasol-reputation/src/lib.rs`, `crates/pasol-reputation/tests/goldens.rs`, `fixtures/golden/reputation/`, `.github/workflows/schema-drift.yml`.
### Tests run
`cargo test -p pasol-reputation --test goldens`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
Four golden tests, workspace tests, and Clippy passed on Windows. The 27 executable workspace tests and documentation tests completed successfully.
### Commit
`1253639`.
### Checklist changes
Deterministic reputation/error goldens and schema-drift workflow coverage are recorded in `TEST-EVIDENCE.md`; J6 remains open for property/fuzz, documentation, and final acceptance.
### Known limitations
CI has not been executed in this environment; workflow action pinning and scheduled fuzz campaigns remain open.
### Remaining work
Add property tests and fuzz targets for reputation parsing, timestamps, cache keys, eviction, conflicts, and error mapping; complete provider/privacy documentation and final J acceptance evidence.
### Next exact action
Add property-based tests for SHA-256 parsing, expiration boundaries, cache-key invalidation, deterministic eviction, conflict resolution, and CLI error-class mapping.

## 2026-08-04 — Reputation property invariants
### Planned work
Add bounded property tests for the Phase J invariants identified in the current milestone.
### Work completed
Added `proptest`-backed SHA-256, cache-key, and store round-trip properties, plus deterministic tests for ordering independence, conflict resolution, source-revision invalidation, and expiration misses.
### Files changed
`Cargo.toml`, `Cargo.lock`, `crates/pasol-reputation/Cargo.toml`, `crates/pasol-reputation/tests/properties.rs`.
### Tests run
`cargo fmt --all`; `cargo test -p pasol-reputation --test properties --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Five property/invariant tests passed on Windows; Clippy passed with warnings denied.
### Commit
`31e24f1`.
### Checklist changes
J7 property validation is recorded in `TEST-EVIDENCE.md`; fuzzing, documentation, and J8 acceptance remain open.
### Known limitations
Fuzz targets are not yet present in this repository; deterministic eviction and error-class mapping need broader dedicated properties.
### Remaining work
Add bounded fuzz targets and compile them, then complete reputation documentation and final acceptance evidence.
### Next exact action
Create the Phase J fuzz workspace and add bounded targets for reputation reports, CLI errors, local stores, caches, imports, hashes, timestamps, conflicts, and cache keys.

## 2026-08-04 — Reputation fuzz-target compilation
### Planned work
Create and compile bounded Phase J fuzz targets for parsing, validation, state resolution, expiration, and round trips.
### Work completed
Added seven standalone libFuzzer binaries with 1 MiB input caps, 4 MiB serialization caps, schema validation, fixed-clock state checks, and no file/network side effects. Added a CI compile step and ignored fuzz build artifacts.
### Files changed
`fuzz/Cargo.toml`, `fuzz/fuzz_targets/*.rs`, `fuzz/.gitignore`, `.github/workflows/schema-drift.yml`.
### Tests run
`cargo fmt --manifest-path fuzz/Cargo.toml --all`; `cargo check --manifest-path fuzz/Cargo.toml --bins`.
### Results
All seven fuzz targets compiled successfully on Windows.
### Commit
`d770c90`; cleanup `585b0cf`.
### Checklist changes
J7 fuzz targets implemented and compile-verified in `TEST-EVIDENCE.md`; scheduled fuzzing and corpus regression remain unchecked.
### Known limitations
`cargo-fuzz` is not installed locally, so no native fuzz campaign was run. The workflow currently compiles targets but does not schedule campaigns.
### Remaining work
Add scheduled bounded fuzz campaigns and regression-corpus handling, then complete reputation documentation and final acceptance evidence.
### Next exact action
Complete the Phase J reputation provider, store, cache, privacy, and threat-model documentation and reconcile the remaining acceptance checkboxes.

## 2026-08-04 — Reputation documentation closure
### Planned work
Finalize the Phase J provider, store, privacy, and threat-model documentation.
### Work completed
Documented all reputation states, conflict and expiration semantics, store/cache limits and invalidation, atomic persistence and import rollback, CLI exit classes and JSON errors, offline privacy guarantees, corruption recovery, and non-enforcement boundaries.
### Files changed
`docs/REPUTATION-PROVIDERS.md`, `docs/LOCAL-REPUTATION-STORE.md`, `docs/REPUTATION-PRIVACY.md`, `docs/REPUTATION-THREAT-MODEL.md`.
### Tests run
Documentation review against the Phase J acceptance requirements.
### Results
All required documentation topics are present; Windows ACL hardening remains explicitly open.
### Commit
`14d9849`.
### Checklist changes
J8 documentation review is recorded in `TEST-EVIDENCE.md`; scheduled fuzzing, corpus regression, and final acceptance remain open.
### Known limitations
No scheduled fuzz campaign has run locally; CI workflow activation remains unverified.
### Remaining work
Reconcile final Phase J acceptance checkboxes and record unresolved risks/deferred work.
### Next exact action
Reconcile the Phase J acceptance checklist, risks, deferred work, and final evidence without marking scheduled fuzzing or CI execution complete.

## 2026-08-04 — Hosted fuzz workflow and regression corpus
### Planned work
Add hosted compile/replay and scheduled smoke workflows with deterministic initial corpora for all seven fuzz targets.
### Work completed
Added a pull-request workflow that compiles and replays all targets, a scheduled bounded smoke workflow with pinned actions and safe artifact handling, and 14 harmless corpus seeds across seven target directories.
### Files changed
`.github/workflows/reputation-fuzz.yml`, `fuzz/corpus/`.
### Tests run
Workflow and corpus structural review; local fuzz-target compile evidence from `cargo check --manifest-path fuzz/Cargo.toml --bins`.
### Results
All target names and corpus paths align. Hosted execution was not available locally and is not claimed.
### Commit
`f983b1c`.
### Checklist changes
Fuzz workflow and initial corpus implementation are recorded in `TEST-EVIDENCE.md`; hosted smoke, corpus replay, and final acceptance remain open.
### Known limitations
No hosted workflow run, campaign duration result, crash/timeout count, or regression replay result is available yet.
### Remaining work
Run the workflow in GitHub, record links and results, then finalize Phase J acceptance without activating Phase I.
### Next exact action
Run and inspect the hosted reputation-fuzz workflow, record its compile/replay/smoke results, and prepare the final Phase J acceptance evidence.

## 2026-08-04 — Reputation store and CLI hardening
### Planned work
Add the clock abstraction, transactional import/export, deterministic store behavior, and actual-binary CLI coverage.
### Work completed
Added typed SHA-256/provider contracts, fixed UTC clock handling, bounded store loading, atomic reopen-and-validate writes, reject-duplicate import, deterministic export, format validation, and two actual-binary CLI tests.
### Files changed
`crates/pasol-reputation/`, `crates/pasol-lab/src/main.rs`, `crates/pasol-lab/tests/reputation_cli.rs`, schemas, and plans.
### Tests run
`cargo fmt --all`; `cargo test -p pasol-reputation --all-features`; `cargo test -p pasol-lab --test reputation_cli`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
All passed on Windows.
### Commit
`6c9f199`.
### Checklist changes
J1–J3 core marked complete; J5 marked in progress; J4/J6 remain open.
### Known limitations
Persistent cache, golden reputation reports, fuzz/property tests, schema-drift extension, typed exit classes, and final acceptance are incomplete.
### Remaining work
Implement J4 cache semantics and complete J5/J6 evidence.
### Next exact action
Implement the provider-scoped persistent cache with injected clock, state-specific TTLs, source-revision invalidation, bounded entries, and deterministic eviction.

## 2026-08-04 — Persistent reputation cache
### Planned work
Implement the provider-scoped persistent cache and extend the actual-binary cache test.
### Work completed
Added versioned cache schema, provider/version/query/hash keys, source revision checks, fixed-clock TTL policies, bounded deterministic eviction, atomic reopen validation, corruption handling, and CLI cache integration.
### Files changed
`crates/pasol-reputation/src/lib.rs`, `crates/pasol-lab/src/main.rs`, `crates/pasol-lab/tests/reputation_cli.rs`, `schemas/reputation-cache-1.0.0.schema.json`.
### Tests run
`cargo fmt --all`; `cargo test -p pasol-reputation --all-features`; `cargo test -p pasol-lab --test reputation_cli`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
Five reputation unit tests and two actual-binary CLI tests passed; Clippy passed on Windows.
### Commit
`035c087`.
### Checklist changes
J4 marked complete; final J5/J6 work remains.
### Known limitations
Typed CLI exit classes, structured JSON errors, reputation goldens, schema-drift CI, property/fuzz tests, and final acceptance remain.
### Remaining work
Complete CLI error semantics and regression evidence.
### Next exact action
Implement typed CLI exit classes and structured JSON errors, then extend reputation schema-drift and golden coverage.

## 2026-08-03 — Phase G acceptance closure
### Planned work
Generate deterministic feature goldens and add catalog-driven state coverage.
### Work completed
Added PE32, PE64, and partial parser fixtures/goldens, byte-for-byte regeneration tests, schema validation, and catalog-driven feature coverage for positive, negative, unknown, unsupported, and partial paths.
### Files changed
`fixtures/golden/features/`, `fixtures/pe64-partial-parser-report.json`, `crates/pasol-lab/tests/features.rs`, and planning files.
### Tests run
`cargo fmt --all -- --check`; `cargo test -p pasol-lab --test features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `cargo test --workspace --all-features`.
### Results
All checks passed; 3 feature tests and the full workspace suite passed. Windows incremental cleanup warnings only.
### Commit
`ffa4442`.
### Checklist changes
Phase G golden and catalog coverage items marked complete; G accepted at the Stage 2 foundation level.
### Known limitations
Not-applicable is outside the PE applicability domain; the six-state SDK contract remains tested separately.
### Remaining work
No mandatory G/H implementation work remains. Phase I remains deferred.
### Next exact action
Do not begin Phase I without a new approved milestone and review of the full Stage 2 plan.

## 2026-08-03 — J1/J2/J3 foundation
### Planned work
Implement the first offline reputation foundation slice.
### Work completed
Added the reputation crate, versioned report/store schemas, provider states, local lookup, expiration filtering, conflict handling, atomic store writes, and CLI lookup/list/add/remove/validate commands.
### Files changed
`crates/pasol-reputation/`, `crates/pasol-lab/`, `schemas/`, reputation documentation, and plans.
### Tests run
`cargo fmt --all`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; manual offline CLI smoke test.
### Results
All automated checks passed; known-benign and unknown lookups returned schema-valid reports.
### Commit
`e4df109`.
### Checklist changes
J1 marked complete; J2/J3 marked in progress.
### Known limitations
Cache policy, import/export, full CLI integration tests, golden reputation reports, fuzzing, and complete documentation remain.
### Remaining work
Complete J2/J3 adversarial tests, then implement J4 cache semantics.
### Next exact action
Add actual-binary reputation CLI integration tests for known-benign, known-malicious, suspicious, unknown, expired, malformed, and corrupt-store cases.

## 2026-08-03 — Phase J1 activated
### Planned work
Activate the explicitly approved Phase J offline reputation foundation, limited to J1 contracts and schemas.
### Work completed
Updated the authoritative milestone, acceptance checklist, J milestone, and scope controls. No implementation code changed.
### Files changed
`plans/CURRENT-MILESTONE.md`, `plans/ACCEPTANCE-CHECKLIST.md`, `plans/milestones/J-REPUTATION.md`.
### Tests run
Planning reconciliation only; no code tests were run.
### Results
J1 is active with explicit offline-only non-goals; Phase I remains deferred.
### Commit
Pending planning-only commit.
### Checklist changes
Phase J1 marked in progress; full J remains incomplete.
### Known limitations
No reputation types, schemas, local provider, cache, or CLI have been implemented yet.
### Remaining work
Implement only J1 contracts, descriptors, states, report/store schemas, runtime validation, and serialization tests.
### Next exact action
Define the Phase J reputation types and schema, preserving unknown, unavailable, rate-limited, unauthorized, and provider-error distinctions.

## 2026-08-03 — G/H foundation accepted
### Planned work
Reconcile the accepted Phase G/H status with the authoritative planning system.
### Work completed
Recorded G and H as accepted at the Stage 2 foundation level and cleared the active implementation milestone. Phase I remains deferred.
### Files changed
`plans/CURRENT-MILESTONE.md` and planning records.
### Tests run
No code changes; relied on verified evidence in commits `ffa4442` and `fbd78af`.
### Results
Planning now shows no active milestone and preserves the next-step approval boundary.
### Commit
Pending planning-only commit.
### Checklist changes
G/H accepted; next milestone approval remains open.
### Known limitations
Pattern matching, reputation, additional parsers, and ML remain unimplemented.
### Remaining work
Select and approve the next milestone.
### Next exact action
Approve Phase J offline reputation foundation before implementation begins.

## 2026-08-03 — Schema drift and starter fixtures
### Planned work
Add a checked-in schema validation gate and positive/negative fixtures for the starter rule.
### Work completed
Added `pasol-lab` integration tests for parser-derived features, rule packs, rule goldens, generated reports, and starter positive/negative fixtures. Added the schema-drift CI workflow.
### Files changed
`crates/pasol-lab/tests/schema.rs`, `fixtures/rules/`, `.github/workflows/schema-drift.yml`, planning files.
### Tests run
`cargo fmt --all`; `cargo test --workspace --all-features`; `cargo test --workspace schema`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
### Results
All passed; 2 new schema tests passed; Windows incremental cleanup warnings only.
### Commit
`5627210`.
### Checklist changes
Schema drift gate and starter fixture coverage verified; catalog-wide feature coverage remains open.
### Known limitations
CI action SHA pinning remains open as a separate supply-chain requirement.
### Remaining work
Complete Phase G golden feature reports and per-feature coverage, then formal G/H acceptance review.
### Next exact action
Generate and check in deterministic PE32, PE64, and partial feature golden reports with schema validation.

## 2026-08-03 — Phase H acceptance recorded
### Planned work
Reconcile the final hardening assessment with local planning records.
### Work completed
Recorded Phase H as accepted at the Stage 2 foundation level and moved the current milestone to Phase G acceptance closure.
### Files changed
`plans/CURRENT-MILESTONE.md`, `plans/ACCEPTANCE-CHECKLIST.md`, `plans/TEST-EVIDENCE.md`.
### Tests run
Reviewed existing evidence for `5627210` and `6fa0e1c`; no code changes made.
### Results
The local plan now identifies H as accepted and keeps G golden/per-feature evidence open.
### Commit
Pending planning-only commit.
### Checklist changes
H acceptance is recorded; G remains unchecked for golden outputs and catalog-wide coverage.
### Known limitations
Phase G has not been accepted; Phase I remains deferred.
### Remaining work
Generate and validate PE32, PE64, and partial feature goldens and complete catalog-driven coverage.
### Next exact action
Implement deterministic feature golden generation and byte-for-byte regeneration tests.

## 2026-08-03 — Golden reports and operator matrix
### Planned work
Validate all four rule goldens and cover operators across uncertain states, missing features, and wrong types.
### Work completed
Added the full uncertainty matrix, explicit missing-feature `exists` behavior, wrong-type stability test, and byte-stable/schema-valid checks for match, no-match, not-evaluated, and budget-warning goldens.
### Files changed
`crates/pasol-rules/src/lib.rs`.
### Tests run
`cargo test -p pasol-rules`; full workspace tests; workspace Clippy with warnings denied.
### Results
6 rule tests passed; all workspace tests and Clippy passed.
### Commit
`ff39e83`.
### Checklist changes
Golden rule evidence and operator/state matrix marked complete.
### Known limitations
Schema-drift CI and complete starter-rule fixture coverage remain open.
### Remaining work
Add CI drift gate and starter-rule positive/negative fixtures before formal H acceptance.
### Next exact action
Add schema-drift CI enforcement and starter-rule positive/negative fixture coverage; do not begin Phase I until G/H acceptance evidence is complete.

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
## 2026-08-04 — Hosted fuzz toolchain correction
### Planned work
Run hosted Phase J fuzz verification.
### Work completed
Created the public detection repository, pushed `main`, enabled GitHub Actions, dispatched run 30930784059, and diagnosed a stable/nightly mismatch. Updated the workflow to install and select nightly Rust. Local formatting and workspace tests passed.
### Files changed
`.github/workflows/reputation-fuzz.yml`, `plans/CURRENT-MILESTONE.md`, `plans/RISKS-AND-BLOCKERS.md`, `plans/TEST-EVIDENCE.md`.
### Tests run
`cargo fmt --check`; `cargo test --workspace --all-features`.
### Results
Local checks passed. Hosted run failed before compilation because stable rustc rejected `-Zsanitizer`.
### Commit
Pending focused workflow-fix commit.
### Checklist changes
Detection repository blocker resolved; hosted fuzz acceptance remains unchecked.
### Known limitations
No hosted compile, replay, or smoke campaign evidence yet.
### Remaining work
Commit and push the workflow correction, rerun hosted workflow, capture job logs and artifact counts.
### Next exact action
Push the nightly-toolchain workflow correction and rerun `reputation-fuzz` from `main`.
## 2026-08-04 — Hosted nightly smoke success
### Planned work
Verify hosted Phase J fuzz execution.
### Work completed
Corrected the workflow to select nightly Rust and dispatched run 30931071619.
### Files changed
`.github/workflows/reputation-fuzz.yml`, `plans/`.
### Tests run
Hosted `cargo fuzz build` and seven bounded fifteen-second campaigns.
### Results
Compile and smoke jobs passed; compile-and-replay was skipped on manual dispatch.
### Commit
a6d54ee
### Checklist changes
Hosted smoke evidence recorded; full hosted acceptance remains open pending replay.
### Known limitations
Fourteen corpus seeds have not yet been replayed in hosted CI.
### Remaining work
Enable compile-and-replay for workflow dispatch and rerun.
### Next exact action
Push the manual-dispatch replay change and rerun the workflow.

## 2026-08-04 — Hosted Phase J acceptance
### Planned work
Run the corrected hosted fuzz workflow with compile/replay enabled for manual dispatch and record complete Phase J execution evidence.
### Work completed
Verified the hosted workflow on the pushed `main` commit. Both compile/replay and scheduled-smoke jobs completed successfully.
### Files changed
Planning evidence and acceptance records only.
### Tests run
GitHub Actions workflow `reputation-fuzz` run 30931536513: `cargo fuzz build`; seven target replays with `-runs=20`; seven smoke campaigns with `-max_total_time=15`.
### Results
Seven targets compiled; fourteen corpus seeds replayed; seven campaigns completed; crash count 0; timeout count 0; invariant-failure count 0; no failure artifacts uploaded. Ubuntu 24.04.4, nightly Rust 1.99.0-nightly, cargo-fuzz 0.13.2.
### Commit
`5565e13b41a29d33b208420cf26a481d276e1380` tested; evidence update pending commit.
### Checklist changes
J5, J6, scheduled fuzz, hosted replay/smoke, and J8 acceptance items marked complete with evidence anchors. J is accepted at the offline foundation level.
### Known limitations
Windows MSVC sanitizer execution remains unavailable; hosted Ubuntu execution is the acceptance environment. Release signing infrastructure and broader Stage 2 phases remain open.
### Remaining work
Choose and record the next milestone before starting Phase I, K, or L.
### Next exact action
Select and record the next implementation milestone in `CURRENT-MILESTONE.md` and `DECISIONS.md`.

## 2026-08-04 — I0 MSRV closure and I1 contracts
### Planned work
Close the Rust 1.91 gate, add a permanent MSRV workflow, and implement I1 contract-only types and schemas.
### Work completed
Installed Rust 1.91, verified the full workspace and YARA-X compatibility test, added the MSRV workflow, created `pasol-patterns`, added four schemas, runtime validation, deterministic normalization, bounded types, and contract tests.
### Files changed
Workspace manifests/lockfile, `crates/pasol-patterns/`, pattern schemas, `.github/workflows/msrv.yml`, and planning files.
### Tests run
Rust 1.91 check, workspace tests, Clippy, formatting, dedicated YARA-X compatibility test, and `pasol-patterns` contract tests.
### Results
All commands passed. Eight report statuses are covered; no-match remains distinct from non-evaluated; path, size, ordering, schema, and serialization invariants pass.
### Commit
Pending focused I1 commit.
### Checklist changes
I0 marked accepted; I1 marked active.
### Known limitations
No signed packs, compiler adapter, worker, CLI, starter pack, or file scanning exists yet. Windows incremental cleanup warnings remain non-fatal.
### Remaining work
Complete I1 schema/golden coverage, then begin I2 signed pattern-pack validation.
### Next exact action
Add full runtime request/response schema validation and deterministic I1 golden reports.

## 2026-08-04 — I1 contract hardening
### Planned work
Complete request/response validation, payload binding, typed metadata, applied limits, status semantics, path checks, and negative contract tests.
### Work completed
Added validated JSON methods for all public contracts, framed worker header fields, SHA-256/length binding, typed scalar metadata, typed signature state and verified-pack wrapper, source-path and source-size checks, status/evidence rules, and expanded applied limits.
### Files changed
`crates/pasol-patterns/`, pattern schemas, workspace dependency manifest, and planning files.
### Tests run
`cargo fmt`; `cargo test -p pasol-patterns --all-features`.
### Results
All six focused tests passed.
### Commit
Pending focused I1 hardening commit.
### Checklist changes
I1 remains in progress; contract hardening evidence recorded.
### Known limitations
The checked-in twelve-file golden corpus and full negative regeneration suite remain outstanding. No I2+ functionality was added.
### Remaining work
Add and validate deterministic report/request/worker goldens.
### Next exact action
Create the complete I1 golden corpus through production serialization and add byte-for-byte regeneration tests.

## 2026-08-04 — Phase I0 compatibility slice
### Planned work
Activate Phase I, record the YARA-X engine decision, pin YARA-X 1.19.0 with restricted features, and run a harmless Windows compatibility test.
### Work completed
Activated I0, added the YARA-X ADR and dependency pin, restricted enabled modules, and added a temporary in-memory compile-and-scan test.
### Files changed
`Cargo.toml`, `Cargo.lock`, `crates/pasol-detection-sdk/Cargo.toml`, `crates/pasol-detection-sdk/tests/yara_x_compat.rs`, `docs/adr/ADR-PATTERN-ENGINE.md`, and Phase I planning files.
### Tests run
`cargo test -p pasol-detection-sdk --test yara_x_compat -- --nocapture`; `cargo fmt --check`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`; `rustup run 1.91.0 rustc --version`.
### Results
YARA-X 1.19.0 compiled and the harmless rule matched on Windows Rust 1.97.1. Formatting, workspace tests, and Clippy passed. Rust 1.91.0 is not installed, so MSRV verification is blocked and not claimed.
### Commit
Pending focused I0 commit.
### Checklist changes
Phase I marked active; I0 compatibility remains in progress pending MSRV evidence.
### Known limitations
No worker, schemas, CLI, production pattern packs, or scanning functionality was added. K and L remain inactive.
### Remaining work
Verify the exact Rust 1.91 toolchain, then begin I1 contracts and schemas.
### Next exact action
Run the I0 compatibility test under Rust 1.91 on Windows or an equivalent CI runner and record the result.

## 2026-08-04 — I1 proof boundary and golden corpus
### Planned work
Finish the I1 contract proof boundary, source-line-ending validation, twelve-file deterministic golden corpus, and negative mutation coverage without activating I2.
### Work completed
Changed scan requests to use unverified `PatternPackReference`, restricted verified-pack construction to an internal Verified-state constructor, bound worker payloads to declared size/hash, accepted LF/CRLF/TAB rule source text while rejecting standalone CR/NUL/other controls, and added twelve checked-in pattern goldens with schema and round-trip tests.
### Files changed
`crates/pasol-patterns/src/lib.rs`, `crates/pasol-patterns/tests/contracts.rs`, `schemas/pattern-*.schema.json`, `fixtures/golden/patterns/`, and I1 planning/evidence files.
### Tests run
`cargo +1.91.0 check --workspace --all-targets --all-features`; `cargo +1.91.0 test --workspace --all-features`; `cargo +1.91.0 clippy --workspace --all-targets --all-features -- -D warnings`; `cargo +1.91.0 fmt --all -- --check`.
### Results
All commands exited 0. Workspace tests and pattern contract tests passed; all checked-in goldens validated and round-tripped deterministically.
### Commit
`53ad196` (published to remote `main`; full SHA `53ad196c9d4033b88441f60bae7f1e74721ca87a`).
### Checklist changes
I1 marked complete in the milestone and consolidated acceptance checklist; next action is I2 activation only.
### Known limitations
Pattern signing, YARA-X production compilation, worker execution, CLI, and file scanning remain unimplemented by design.
### Remaining work
Create an I2 planning activation for signed pattern-pack validation.
### Next exact action
Activate I2 signed pattern-pack validation in planning before changing implementation code.

## 2026-08-05 — I2 planning activation
### Planned work
Activate I2 as the sole implementation milestone for shared trust extraction and bounded signed pattern-pack validation.
### Work completed
Updated milestone, acceptance, decision, and risk records. I3, K, and L remain inactive; compiler, worker, CLI, scanning, uploads, verdicts, and enforcement remain excluded.
### Files changed
Planning files under `plans/`.
### Tests run
Repository and remote-state inspection only; no production code changed.
### Results
Starting commit `890a9a7e2e7566ac468c7dce176212a1530e8c33` was confirmed clean and current before activation.
### Commit
Pending planning activation commit.
### Checklist changes
I2 marked in progress; I3 remains unchecked.
### Known limitations
Trust extraction and all pattern-pack implementation work remain outstanding.
### Remaining work
Extract `pasol-trust` while preserving Phase H behavior.
### Next exact action
Create `pasol-trust` and migrate the existing rules trust implementation without changing Phase H schemas or behavior.

## 2026-08-05 — Shared trust extraction
### Planned work
Move generic Ed25519 trusted-key storage and verification primitives from `pasol-rules` into `pasol-trust` while preserving Phase H behavior.
### Work completed
Added `pasol-trust` with versioned key-store types, active/retired/revoked resolution, unknown/invalid-key rejection, atomic persistence, and compatibility re-exports from `pasol-rules`.
### Files changed
Workspace manifest, `crates/pasol-trust/`, and `crates/pasol-rules/`.
### Tests run
`cargo +1.91.0 fmt --all`; `cargo +1.91.0 test -p pasol-trust -p pasol-rules --all-features`; `cargo +1.91.0 clippy -p pasol-trust -p pasol-rules --all-targets --all-features -- -D warnings`.
### Results
Three trust tests and six existing rules tests passed; formatting and Clippy passed.
### Commit
Pending focused trust extraction commit.
### Checklist changes
I2 shared trust work remains in progress pending integration into `pasol-patterns` and full workspace evidence.
### Known limitations
Pattern manifests, detached signatures, canonical signing, and bundle verification are not yet implemented.
### Remaining work
Add pattern manifest and detached-signature contracts.
### Next exact action
Implement versioned pattern manifest and detached signature types with schema and semantic validation.

## 2026-08-05 — Pattern manifest and detached signatures
### Planned work
Add typed versioned pattern manifests, detached Ed25519 signatures, canonical signing messages, exact source hashing, and bounded in-memory verification.
### Work completed
Added manifest/signature types and schemas, semantic engine/path/version/hash validation, canonical manifest bytes and digest helpers, domain-separated deterministic signing, bounded source verification, trusted-key resolution, and production verified-pack construction.
### Files changed
`crates/pasol-patterns/src/manifest.rs`, `crates/pasol-patterns/src/lib.rs`, pattern schemas, and pattern contract tests.
### Tests run
`cargo +1.91.0 fmt --all`; `cargo +1.91.0 test -p pasol-patterns --all-features`; `cargo +1.91.0 clippy -p pasol-patterns --all-targets --all-features -- -D warnings`.
### Results
Three unit tests and eight pattern integration tests passed; formatting and Clippy passed.
### Commit
Pending focused manifest/signature commit.
### Checklist changes
Manifest/signature and bounded verification items remain in progress pending full workspace and adversarial coverage.
### Known limitations
Fuzz targets, hosted CI, full golden pack fixtures, and I2 documentation are not yet complete.
### Remaining work
Add adversarial/property coverage, fixtures, fuzz targets, CI, and documentation.
### Next exact action
Add complete I2 manifest/source/key mutation and property tests, then add deterministic pack goldens.

## 2026-08-05 — I2 adversarial coverage, fuzz targets, and documentation
### Planned work
Harden I2 with manifest/source mutation tests, bounded properties, fuzz-target compilation, read-only workflow integration, deterministic harmless seeds, and trust/privacy/threat-model documentation.
### Work completed
Added manifest mutation rejection, source tamper/revocation tests, canonicalization property testing, three I2 fuzz targets and seeds, workflow target integration, and six I2 trust/format documentation files.
### Files changed
`crates/pasol-patterns/tests/contracts.rs`, `fuzz/`, `.github/workflows/reputation-fuzz.yml`, and `docs/PATTERN-PACK*.md` plus trust/signature ADRs.
### Tests run
`cargo +1.91.0 fmt --all`; `cargo +1.91.0 test -p pasol-patterns --all-features`; `cargo +1.91.0 clippy -p pasol-patterns --all-targets --all-features -- -D warnings`; `cargo +1.91.0 check --manifest-path fuzz/Cargo.toml --bins`.
### Results
Pattern tests: 10 passed. Pattern Clippy and formatting passed. All ten fuzz binaries compiled under Rust 1.91. The combined full-workspace command exceeded the 300-second local timeout before producing a result and is not claimed as passed.
### Commit
Pending focused I2 coverage/docs commit.
### Checklist changes
I2 adversarial/property, fuzz compilation, CI, and documentation items are partially implemented; acceptance remains open.
### Known limitations
Hosted I2 workflow has not run; no production key or private key is committed; full workspace gate needs a separate run.
### Remaining work
Add deterministic signed-pack fixtures/goldens, complete schema-drift coverage, run hosted workflow, and reconcile final acceptance evidence.
### Next exact action
Add signed-valid, multi-source, and development fixture bundles plus deterministic manifest/signature/identity verification goldens.

## 2026-08-05 — I2 signed fixtures and trust goldens
### Planned work
Add harmless signed, multi-source, and development bundles plus deterministic manifest, detached-signature, identity, source-index, and verification-summary goldens.
### Work completed
Added fixed test-key fixture bundles, six trust goldens, and production verification tests covering signed success, development rejection through the production API, exact source hashes, and trusted-key identity.
### Files changed
`fixtures/pattern-packs/`, `fixtures/golden/pattern-packs/`, and pattern contract tests.
### Tests run
`cargo +1.91.0 fmt --all`; `cargo +1.91.0 test -p pasol-patterns --all-features`; `cargo +1.91.0 clippy -p pasol-patterns --all-targets --all-features -- -D warnings`.
### Results
Three unit and eleven integration tests passed; formatting and Clippy passed.
### Commit
Pending focused fixture/golden commit.
### Checklist changes
I2 fixture, golden, and production/development proof-boundary coverage advanced; hosted and full-workspace evidence remain open.
### Known limitations
The fixed key is test-only and no private key is stored. Full hosted I2 workflow has not run.
### Remaining work
Add schema-drift checks for trust schemas, run full Rust 1.91 workspace gates, and obtain hosted fuzz evidence.
### Next exact action
Extend schema-drift and CI workflow coverage for trust/pattern schemas, then run all workspace gates.

## 2026-08-05 — I2 local workspace gate
### Planned work
Run the full Rust 1.91 workspace and fuzz compilation gates after I2 trust, manifest, fixture, and documentation changes.
### Work completed
Validated the complete workspace, all pattern/trust tests, Clippy, formatting, and all ten fuzz binaries; extended the schema-drift matrix with trust and pattern contract tests.
### Files changed
`.github/workflows/schema-drift.yml`.
### Tests run
`cargo +1.91.0 check --workspace --all-targets --all-features`; `cargo +1.91.0 test --workspace --all-features`; `cargo +1.91.0 clippy --workspace --all-targets --all-features -- -D warnings`; `cargo +1.91.0 fmt --all -- --check`; `cargo +1.91.0 check --manifest-path fuzz/Cargo.toml --bins`.
### Results
All commands exited 0. The prior combined run exceeded a timeout during a cold rebuild; the individual gates subsequently completed successfully.
### Commit
Pending schema-drift workflow commit.
### Checklist changes
Local I2 quality evidence is recorded; hosted evidence remains open.
### Known limitations
No hosted I2 workflow run has been executed; no pattern matching or worker code exists by design.
### Remaining work
Run hosted I2 workflow, record evidence, and close or retain blockers honestly.
### Next exact action
Push the schema-drift workflow update and dispatch the hosted I2 verification workflow.

## 2026-08-05 — I2 hosted workflow activation
### Planned work
Enable the pinned I2 workflow for manual, pull-request, and main-branch execution so hosted Windows/Ubuntu evidence can be collected.
### Work completed
Added main-branch triggering to the read-only `pattern-pack-i2` workflow; it runs Rust 1.91 workspace checks, tests, Clippy, formatting, and fuzz-target compilation on both operating systems.
### Files changed
`.github/workflows/pattern-pack-i2.yml`.
### Tests run
Local workflow/YAML inspection; local equivalents are recorded in the prior workspace-gate entry.
### Results
Workflow is committed and will execute on the next push.
### Commit
Pending hosted-workflow trigger commit.
### Checklist changes
Hosted I2 evidence remains unchecked until a real workflow run completes.
### Known limitations
This environment does not expose a workflow-dispatch API; push-triggered execution is used instead.
### Remaining work
Inspect the hosted run, record runner/toolchain/test/fuzz results, and resolve any failures.
### Next exact action
Push the workflow trigger and retrieve the resulting GitHub Actions run evidence.
## 2026-08-05 — Harden trust schema loading and hosted I2 workflow
### Planned work
Close the trust-schema validation gap and make the Windows/Ubuntu hosted I2 workflow shell-portable.
### Work completed
Added runtime validation of trusted-key-store JSON against schema 1.0.0 before deserialization and removed the PowerShell-only workflow shell declaration.
### Files changed
`crates/pasol-trust/Cargo.toml`, `crates/pasol-trust/src/lib.rs`, `Cargo.lock`, `.github/workflows/pattern-pack-i2.yml`.
### Tests run
Rust 1.91 formatting, pasol-trust tests, pasol-patterns tests, and Clippy with warnings denied.
### Results
All local commands passed; 3 trust tests and 14 pattern tests passed.
### Commit
Pending.
### Checklist changes
Trust schema runtime validation is now evidenced locally; I2 remains in progress pending hosted workflow evidence.
### Known limitations
The earlier hosted run `30997918594` remained in progress with 0/2 jobs completed; replacement-run evidence is required.
### Remaining work
Push the correction, verify the replacement workflow on Ubuntu and Windows, and record its URL and matrix results.
### Next exact action
Commit and push this focused correction, then inspect the replacement `pattern-pack-i2` workflow run.

## 2026-08-05 — Make deterministic goldens cross-platform
### Planned work
Resolve the Windows hosted golden mismatch without weakening byte-for-byte assertions.
### Work completed
Added `.gitattributes` with repository-wide LF checkout policy and recorded the observed Windows-only newline failure.
### Files changed
`.gitattributes`, planning evidence files.
### Tests run
The failing hosted job log was inspected; local Windows tests already pass.
### Results
The portability correction is ready for hosted verification.
### Commit
Pending.
### Checklist changes
Cross-platform golden portability remains open pending a successful replacement run.
### Known limitations
Hosted runs are still compiling on both runner families.
### Remaining work
Push the newline policy and wait for the latest workflow run.
### Next exact action
Commit and push the cross-platform golden fix, then record the replacement run’s matrix results.

## 2026-08-05 — Hosted I2 matrix passed
### Planned work
Verify the corrected I2 workflow on Ubuntu and Windows.
### Work completed
The hosted matrix completed workspace check, tests, Clippy, formatting, and fuzz-target compilation successfully on both runners.
### Files changed
Planning evidence only.
### Tests run
Workflow `pattern-pack-i2.yml`, run `30998466615`, commit `b9a53f5`.
### Results
Ubuntu job `92281197538` and Windows job `92281197472` both passed. Ten fuzz binaries compiled; no campaigns were executed by this contract workflow.
### Commit
Pending evidence commit.
### Checklist changes
Cross-platform hosted contract evidence can be marked complete; campaign-execution evidence remains open.
### Known limitations
The workflow does not run fuzz campaigns, and I2 acceptance must not claim campaign results from compilation alone.
### Remaining work
Reconcile the I2 checklist, decide whether hosted campaign execution is required for this milestone, and record any remaining blockers.
### Next exact action
Commit the hosted evidence update and review every open I2 checkbox before any I3 activation.

## 2026-08-05 — Add current-commit pattern fuzz campaign workflow
### Planned work
Provide hosted replay and bounded smoke evidence for the three I2 pattern-pack fuzz targets.
### Work completed
Added a pinned Ubuntu workflow with push-triggered corpus replay, manual/scheduled 15-second smoke campaigns, and failure-only artifact upload.
### Files changed
`.github/workflows/pattern-pack-fuzz.yml`, planning files.
### Tests run
Workflow definition inspection; hosted execution pending after push.
### Results
The workflow is bounded and read-only; no current-commit campaign result exists yet.
### Commit
Pending.
### Checklist changes
I2 fuzz evidence remains unchecked.
### Known limitations
No worker or compiler execution is introduced; fuzz targets only exercise manifest, signature, and bundle-validation code.
### Remaining work
Push and inspect the current-commit workflow run, then record counts and outcomes.
### Next exact action
Commit and push the dedicated fuzz workflow and wait for its replay result.

## 2026-08-05 — Current-commit pattern fuzz replay passed
### Planned work
Verify the dedicated pattern fuzz workflow on the I2 source tree.
### Work completed
The push-triggered workflow built and replayed all three pattern-pack fuzz targets against their checked-in seeds.
### Files changed
Evidence only; workflow commit `324e83e`.
### Tests run
Run `30999221629`, job `92283658083`.
### Results
Replay passed with no crash, timeout, or invariant failure.
### Commit
`324e83e`.
### Checklist changes
Current-commit replay evidence is complete; bounded smoke evidence remains open.
### Known limitations
The first push-triggered version did not run smoke campaigns; the workflow is being adjusted to run them on push as well.
### Remaining work
Push the smoke-condition correction and record its result.
### Next exact action
Commit and push the smoke-condition correction, then inspect the resulting run.

## 2026-08-05 — Add I3 compiler-adapter planning milestone
### Planned work
Add the supplied planning-only I3 compiler-adapter specification and reconcile all planning records without activating implementation.
### Work completed
Added the complete I3 milestone specification, recorded the separate compiler crate and strict YARA-X policy decision, added I3 risks, and updated milestone and acceptance checklists.
### Files changed
`plans/milestones/I3-COMPILER-ADAPTER.md`, `plans/CURRENT-MILESTONE.md`, `plans/milestones/I-PATTERN-MATCHING.md`, `plans/ACCEPTANCE-CHECKLIST.md`, `plans/DECISIONS.md`, `plans/RISKS-AND-BLOCKERS.md`, and this log.
### Tests run
Planning-state inspection only; no production-code tests were run or required.
### Results
No Rust, schema, fixture, CI, compiler, worker, scanner, or enforcement files changed.
### Commit
Pending.
### Checklist changes
I3 planning marked complete; I3 implementation remains unchecked.
### Known limitations
I3 implementation is not authorized and all compiler risks remain open.
### Remaining work
Obtain explicit approval before activating I3 as the sole implementation milestone.
### Next exact action
Explicitly approve I3 implementation, then update `CURRENT-MILESTONE.md` before changing production code.
