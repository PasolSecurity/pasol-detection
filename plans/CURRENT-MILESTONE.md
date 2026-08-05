# Current Milestone

## Milestone
Phase I — Bounded Pattern Matching
I3 — YARA-X Compiler Adapter Validation

## Objective
Convert an already validated `VerifiedPatternPack` or explicitly loaded `DevelopmentPatternPack` into bounded, deterministic, in-memory YARA-X compiled rules under a strict Pasol-owned compiler policy, without scanning, worker execution, CLI exposure, persistence, or verdicts.

## Approved scope
- I3 is the sole active implementation milestone, activated by explicit approval on 2026-08-05.
- Dedicated `pasol-pattern-compiler` crate depending on `pasol-patterns`, never the reverse.
- Proof-carrying entry points only: separate verified and development functions.
- Versioned compiler report, diagnostics, policy, limits, and typed errors.
- Strict YARA-X configuration: includes disabled, relaxed regular-expression syntax disabled, slow patterns and slow loops rejected, zero compiler warnings tolerated.
- Module allowlist of exactly `pe`, `hash`, `math`, and `string`, with post-build import audit.
- Metadata policy `pasol-pattern-metadata-1`, tag policy, and prohibition of global rules.
- Deterministic reports, goldens, adversarial and property tests, bounded fuzzing, hosted CI, and documentation.
- Execution follows the slices I3.1 through I3.8 in `milestones/I3-COMPILER-ADAPTER.md`.

## Explicit non-goals
Do not begin I4, I5, Phase K, or Phase L. Do not add pattern scanning of files, folders, processes, or memory; `yara_x::Scanner` construction; worker-process execution; Windows Job Objects; hard wall-clock or memory limits; CLI pattern commands; filesystem pack discovery or directory walking; compiled-rule persistence or deserialization; network access; uploads; telemetry; blocking; quarantine; deletion; remediation; enforcement; or antivirus verdicts.

Do not refactor `pasol-patterns` module structure during the first I3 implementation slice. That work is recorded as deferred item I2-H3.

## Dependencies
Accepted G/H/J foundation and accepted I0, I1, and I2 pattern foundation. I2 remains accepted at the signed pattern-pack foundation level; its hardening items I2-H1, I2-H2, and I2-H3 are deferred and do not gate I3.

## Tasks
- [x] Close Phase G acceptance evidence.
- [x] Close Phase H acceptance evidence.
- [x] Complete J1–J8 offline reputation foundation and hosted evidence.
- [x] Select and activate Phase I explicitly.
- [x] Complete I0 YARA-X compatibility, ADR, and harmless in-memory test.
- [x] Complete I1 contracts, schemas, runtime validation, deterministic serialization, proof-boundary checks, and golden corpus.
- [x] Complete I2 signed pattern-pack validation, trust verification, hosted replay, and bounded smoke evidence.
- [x] Planning-only I3 activation.
- [ ] I3.1 crate and report contracts.
- [ ] I3.2 strict compiler construction.
- [ ] I3.3 deterministic source ingestion.
- [ ] I3.4 post-build policy audit.
- [ ] I3.5 deterministic reports and goldens.
- [ ] I3.6 adversarial and property coverage.
- [ ] I3.7 fuzzing, CI, and documentation.
- [ ] I3.8 hosted evidence and formal closure.

## Files expected to change
`plans/` only in the activation commit. From I3.1 onward: `crates/pasol-pattern-compiler/`, `schemas/pattern-compiler-report-1.0.0.schema.json`, workspace `Cargo.toml` and `Cargo.lock`, compiler fixtures and goldens, `fuzz/`, `.github/workflows/`, and `docs/` compiler files. Do not change `crates/pasol-patterns/` module structure.

## Tests required
Under Rust `1.91.0` on Windows and Ubuntu: workspace check, workspace tests, `pasol-pattern-compiler` tests, `pasol-patterns` tests, Clippy with warnings denied, and formatting. Plus compiler report schema drift, golden report regeneration, fuzz-target compilation, corpus replay, and bounded hosted Ubuntu compiler smoke campaigns.

## Security checks required
Do not introduce scanning, scanner construction, worker execution, CLI commands, filesystem pack discovery, compiled-rule persistence or deserialization, external globals, ignored modules, uploads, credentials, verdicts, blocking, quarantine, deletion, or enforcement. Preserve the I2 proof boundary so no raw or unverified source can reach the compiler.

## Documentation required
`docs/PATTERN-COMPILER.md`, `docs/PATTERN-COMPILER-POLICY.md`, `docs/PATTERN-COMPILER-THREAT-MODEL.md`, and `docs/adr/ADR-PATTERN-COMPILER-BOUNDARY.md`, including the explicit statement that hard in-process time and memory isolation does not exist until I4.

## Acceptance gate
Every item in the I3 acceptance gate in `milestones/I3-COMPILER-ADAPTER.md` must pass with recorded evidence before I3 is marked accepted.

## Current status
I3 is the sole active implementation milestone. I0, I1, and I2 are accepted and their acceptance records are unchanged. I2 hardening items I2-H1, I2-H2, and I2-H3 are recorded in `DEFERRED-WORK.md` and are not part of I3. I4, I5, K, and L remain inactive.

## Next exact action
Begin slice I3.1: add the `pasol-pattern-compiler` crate with policy, limit, report, diagnostic, error, failure, and compiled proof types, add `schemas/pattern-compiler-report-1.0.0.schema.json` with runtime validation and deterministic normalization, and do not call YARA-X beyond the accepted compatibility test.
