# Risks and blockers

## Windows incremental-directory locking
- Status: Resolved
- Severity: Low
- Area: Build tooling
- Description: Rust sometimes reports Access Denied while finalizing incremental directories.
- Impact: No observed test/build failure; cleanup noise can obscure failures.
- Mitigation: Record warning; inspect running cargo/rustc/IDE processes before cleanup.
- Owner: Maintainers
- Introduced: 2026-08-03
- Target resolution: CI and developer documentation
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-03-windows-validation`

## I2 trust-layer extraction compatibility
- Status: Resolved
- Severity: High
- Area: I2 shared trust
- Description: Generic Ed25519 key-store behavior lived in `pasol-rules` and had to be extracted without changing Phase H formats or verification semantics.
- Impact: None observed. `pasol-trust` owns the shared key store and verification, `pasol-rules` re-exports the public types, and Phase H rule-pack trust behavior is unchanged.
- Mitigation: Public rule types were preserved by re-export and the Phase H suite was rerun after the extraction.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I2.1 shared trust extraction
- Resolution evidence: Commit `07546b3`; re-verified at `6a6bed3` with `cargo +1.91.0 test -p pasol-rules --all-features` passing 6 tests and `-p pasol-trust --all-features` passing 4 tests.

## I2 signing infrastructure
- Status: Open
- Severity: Medium
- Area: I2 fixtures and release
- Description: Production signing keys and protected release environments are not available in the repository.
- Impact: Only ephemeral in-test signatures can be verified during I2.
- Mitigation: Generate test keys in memory, never commit private keys, and defer production signing to protected environments.
- Owner: Release maintainers
- Introduced: 2026-08-05
- Target resolution: Protected release setup before signed distribution
- Resolution evidence: Pending

## Missing release signing infrastructure
- Status: Open
- Severity: High
- Area: H/release
- Description: Production private signing keys and protected environments are not available in this repository.
- Impact: No public signed release can be claimed.
- Mitigation: Keep test keys ephemeral; require protected release environment.
- Owner: Release maintainers
- Introduced: 2026-08-03
- Target resolution: Before H release acceptance
- Resolution evidence: Pending

## Phase I MSRV toolchain unavailable
- Status: Resolved
- Severity: Medium
- Area: Phase I compatibility
- Description: The workspace declares Rust 1.91, and YARA-X 1.19.0 declares Rust 1.91.0, but the current Windows host has only 1.85.0, 1.97.1, and nightly toolchains installed.
- Impact: None after exact Windows verification; CI remains configured to prevent regressions.
- Mitigation: Keep the pinned MSRV workflow running on pull requests.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: Before Phase I1 implementation
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-04-phase-i0-msrv-and-i1-contracts`.

## Golden evidence and schema drift
- Status: Open
- Severity: Medium
- Area: J testing
- Description: Reputation goldens and the schema-drift workflow are checked in, but hosted CI execution has not been verified locally.
- Impact: Cross-platform hosted execution remains unconfirmed.
- Mitigation: Workflow includes Ubuntu and Windows matrices; retain local evidence as separate from hosted-run evidence.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: First successful hosted workflow run
- Resolution evidence: Pending

## Fuzz campaign availability
- Status: Resolved
- Severity: Medium
- Area: J7 validation
- Description: Seven fuzz targets and fourteen harmless seeds now compile, replay, and execute in hosted Linux CI.
- Impact: Local Windows sanitizer execution remains unavailable, but hosted campaign evidence is available.
- Mitigation: Keep the compile/replay gate active and preserve minimized regressions.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: Resolved 2026-08-04
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`; workflow run 30931536513.

## Detection repository unavailable
- Status: Resolved
- Severity: High
- Area: Hosted CI and release
- Description: GitHub API and authenticated Git push both report `PasolSecurity/pasol-detection` as not found; only `PasolSecurity/pasol-parser` is visible.
- Impact: Hosted fuzz workflows cannot run and no pull-request or release evidence can be recorded.
- Mitigation: Create the detection repository under the PasolSecurity organization or grant the authenticated account access, then push the current branch.
- Owner: Repository administrator
- Introduced: 2026-08-04
- Target resolution: Before Phase J acceptance
- Resolution evidence: Public repository created and `main` pushed; hosted run 30930784059.

## Hosted fuzz workflow stable-toolchain mismatch
- Status: Resolved
- Severity: High
- Area: J hosted fuzzing
- Description: Hosted `cargo fuzz build` used stable Rust while cargo-fuzz passed nightly-only `-Zsanitizer` flags.
- Impact: Manual run 30930784059 failed before compiling fuzz targets.
- Mitigation: Pin and select nightly Rust in the workflow before rerunning.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: Next hosted fuzz run
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`; workflow run 30931536513.

## Windows sanitizer runtime limitation
- Status: Resolved
- Severity: Medium
- Area: J fuzz execution
- Description: cargo-fuzz targets compile with nightly but Windows MSVC linking fails on sanitizer-coverage symbols.
- Impact: Local Windows smoke campaigns cannot provide execution evidence.
- Mitigation: Use hosted Ubuntu fuzz jobs for execution; retain Windows as a compile/schema platform.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: 2026-08-04
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`; workflow run 30931536513.
## Risk or blocker
- Status: Resolved
- Severity: Medium
- Area: Hosted I2 verification
- Description: The first hosted pattern-pack workflow run (`30997918594`) failed on Windows because checked-in LF goldens were read as CRLF.
- Impact: Cross-platform byte-for-byte golden evidence was initially unavailable.
- Mitigation: Added `.gitattributes` with LF checkout policy and reran the complete matrix.
- Owner: PasolSecurity maintainers
- Introduced: 2026-08-05
- Target resolution: 2026-08-05
- Resolution evidence: `plans/TEST-EVIDENCE.md#2026-08-05--hosted-i2-contract-verification`; workflow run `30998466615`.

## Risk or blocker
- Status: Resolved
- Severity: Medium
- Area: I2 fuzz evidence
- Description: The hosted I2 workflow compiles ten fuzz binaries but does not execute bounded fuzz campaigns.
- Impact: Campaign crash, timeout, invariant, and corpus-replay evidence was initially unavailable for formal acceptance.
- Mitigation: Added `.github/workflows/pattern-pack-fuzz.yml`; current-commit replay and bounded smoke campaigns passed.
- Owner: PasolSecurity maintainers
- Introduced: 2026-08-05
- Target resolution: 2026-08-05
- Resolution evidence: `plans/TEST-EVIDENCE.md#2026-08-05--current-commit-pattern-fuzz-smoke-passed`; workflow run `30999489110`.

## Deferred I2 hardening reduces generative assurance depth
- Status: Open
- Severity: Low
- Area: I2 test depth
- Description: I2 was accepted with one property-test block instead of the specified invariant set, three fuzz corpus seeds instead of ten semantic seed categories, and a two-module `pasol-patterns` instead of the specified eight-module layout. Tracked as `I2-H1`, `I2-H2`, and `I2-H3`.
- Impact: All affected invariants retain deterministic example-based coverage and passed hosted bounded fuzz campaigns, so no invariant is unverified. The residual risk is a lower probability of discovering an unanticipated counterexample, plus reduced maintainability of a 820-line `lib.rs`.
- Mitigation: Gaps are recorded explicitly rather than silently; hosted smoke campaigns remain active on every push; the module split is barred from the first I3 slice so it cannot be conflated with compiler-adapter review.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: A scheduled I2-H hardening slice, promoted earlier if I3 uncovers a defect attributable to a deferred item.
- Resolution evidence: Pending

## Risk or blocker
- Status: Open
- Severity: High
- Area: I3 in-process compiler resource exhaustion
- Description: Compiler policy runs in-process until I4 worker isolation exists.
- Impact: A malformed or adversarial validated pack could consume excessive compiler resources.
- Mitigation: Bounded proof-carrying inputs, slow-pattern and slow-loop rejection, strict limits, fuzzing, and mandatory I4 isolation before external use.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I4 worker milestone
- Resolution evidence: Pending

## Risk or blocker
- Status: Open
- Severity: Medium
- Area: I3 engine API and diagnostic drift
- Description: YARA-X compiler APIs or diagnostics may change across upgrades.
- Impact: Reports, policy enforcement, and deterministic goldens could drift.
- Mitigation: Pin YARA-X 1.19.0, version reports and policy, sanitize diagnostics, and require explicit upgrade decisions.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I3 acceptance
- Resolution evidence: Pending

## Risk or blocker
- Status: Open
- Severity: Medium
- Area: I3 warning policy
- Description: Zero-warning rejection may over-reject otherwise usable rules.
- Impact: Compatibility and adoption may be reduced.
- Mitigation: Fail closed initially; any exception requires a policy-version decision and evidence.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I3 policy review
- Resolution evidence: Pending

## Risk or blocker
- Status: Open
- Severity: High
- Area: I3 module-policy drift
- Description: Future engine modules may be introduced without an explicit allowlist decision.
- Impact: Rules could access unsupported or unsafe module behavior.
- Mitigation: Keep the exact `pe`, `hash`, `math`, and `string` allowlist, ban other modules, and audit imports after build.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I3 acceptance
- Resolution evidence: Pending

## Risk or blocker
- Status: Open
- Severity: High
- Area: I3 compiled-rule blob misuse
- Description: Serialized compiled rules could be mistaken for portable or trusted artifacts.
- Impact: Manipulated or incompatible compiled bytes could bypass source and manifest identity.
- Mitigation: No persistence, binary goldens, deserialization, or third-party compiled bytes; source manifest remains authoritative.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I3 acceptance
- Resolution evidence: Pending

## Risk or blocker
- Status: Open
- Severity: Medium
- Area: I3 diagnostic information leakage
- Description: Compiler diagnostics may expose host paths, source excerpts, ANSI escapes, or machine-specific data.
- Impact: Reports could leak local information or become nondeterministic.
- Mitigation: Canonical relative origins, bounded sanitized diagnostics, no source excerpts, and deterministic normalization.
- Owner: Detection maintainers
- Introduced: 2026-08-05
- Target resolution: I3 acceptance
- Resolution evidence: Pending
