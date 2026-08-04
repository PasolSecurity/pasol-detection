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
- Status: Open
- Severity: Medium
- Area: J7 validation
- Description: Seven fuzz targets compile and a hosted workflow plus initial corpus are checked in, but `cargo-fuzz` is not installed in the current Windows environment and no hosted campaign or replay has run.
- Impact: Compile coverage exists without campaign-level crash, hang, or allocation evidence.
- Mitigation: Keep the compile/replay gate active; run bounded scheduled campaigns in CI and preserve minimized regressions.
- Owner: Detection maintainers
- Introduced: 2026-08-04
- Target resolution: First scheduled fuzz campaign and corpus check-in
- Resolution evidence: Pending
