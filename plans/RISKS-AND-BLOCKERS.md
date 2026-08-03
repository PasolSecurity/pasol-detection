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
- Area: G/H testing
- Description: Golden reports and CI drift checks are not yet checked in.
- Impact: Regression evidence remains incomplete.
- Mitigation: Current milestone tracks exact next action and acceptance remains unchecked.
- Owner: Detection maintainers
- Introduced: 2026-08-03
- Target resolution: Final G/H slice
- Resolution evidence: Pending
