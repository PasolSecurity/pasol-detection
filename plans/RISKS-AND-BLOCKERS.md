# Risks and blockers

## Windows incremental-directory locking
- Status: Open
- Severity: Low
- Area: Build tooling
- Description: Rust sometimes reports Access Denied while finalizing incremental directories.
- Impact: No observed test/build failure; cleanup noise can obscure failures.
- Mitigation: Record warning; inspect running cargo/rustc/IDE processes before cleanup.
- Owner: Maintainers
- Introduced: 2026-08-03
- Target resolution: CI and developer documentation
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-03-windows-validation`

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
- Status: Open
- Severity: Medium
- Area: Phase I compatibility
- Description: The workspace declares Rust 1.91, and YARA-X 1.19.0 declares Rust 1.91.0, but the current Windows host has only 1.85.0, 1.97.1, and nightly toolchains installed.
- Impact: The I0 compatibility spike cannot yet claim MSRV verification.
- Mitigation: Run the exact compatibility test under Rust 1.91 in CI or install the pinned MSRV toolchain before accepting I0.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: Before Phase I1 implementation
- Resolution evidence: `TEST-EVIDENCE.md#2026-08-04-phase-i0-yara-x-compatibility-spike`.

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
- Status: Open
- Severity: Medium
- Area: J fuzz execution
- Description: cargo-fuzz targets compile with nightly but Windows MSVC linking fails on sanitizer-coverage symbols.
- Impact: Local Windows smoke campaigns cannot provide execution evidence.
- Mitigation: Use hosted Ubuntu fuzz jobs for execution; retain Windows as a compile/schema platform.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: Hosted Linux fuzz run
- Resolution evidence: Pending
