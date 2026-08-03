# Stage 2 master plan

Status markers: `[ ]` not started; `[~]` in progress; `[x]` completed and verified; `[!]` blocked; `[-]` explicitly deferred. A completion mark requires implementation, tests, documentation, inspection, runtime validation, and evidence in `TEST-EVIDENCE.md`.

## Mission and architecture

Stage 2 converts bounded parser facts into versioned, explainable evidence without blocking, deletion, quarantine, execution, upload, or a final antivirus verdict. `pasol-parser` reports facts; `pasol-detection` interprets them. Dependency direction: parser → features → rules → static score, with patterns and reputation beside the feature pipeline.

## Repository and versions

- [x] Detection workspace exists with SDK, features, rules, static score, and lab CLI (commits `00b24b8`, `021e028`).
- [x] Feature, rule-pack, and rule-report schemas use version `1.0.0` where implemented (`03d4f93`, `66b4e42`).
- [ ] Publish `pasol-detection v0.1.0` and parser `v0.2.0`.
- [ ] Preserve parser compatibility and add K parsers in the parser repository.

## Global security requirements

- [x] No inspected-file execution, loading, active rendering, uploads, blocking, deletion, quarantine, or final verdict behavior.
- [ ] Enforce limits for every new parser, pattern worker, archive, report, model, and provider.
- [ ] Complete supply-chain, secret, signing, fuzzing, and release controls.

## G — Security Feature Catalog

- [x] Feature SDK, schema, provenance, evidence, deterministic PE extraction, six states, malformed rejection, and runtime schema validation (`588b349`, `03d4f93`).
- [ ] Checked-in PE32, PE64, and partial golden feature reports with byte-for-byte tests.
- [ ] Positive and negative coverage for every documented feature and state/value combination.
- [ ] Complete catalog documentation and schema-drift CI.
- [ ] Unsupported parser/schema tests and boundary fixtures.

## H — Deterministic Rules Engine

- [x] Declarative evaluator, operators, starter pack, unknown/truncated semantics, depth and resource budgets (`00b24b8`, `588b349`, `66b4e42`).
- [x] Rule-pack/report schemas, runtime validation, Ed25519 structures, manifest verification, trusted-key library, and generated-key tamper tests (`03d4f93`, `a251ba2`, `fe225e4`).
- [ ] Signing and verification CLI with deterministic manifests.
- [ ] Persistent trusted-key lifecycle, rotation, revocation, permissions, and integration tests.
- [ ] Golden rule reports and complete operator/state matrix.

## I — Pattern matching

- [ ] Select and document YARA-X engine.
- [ ] Add isolated worker, timeout/memory/input/rule/output limits, signed packs, schema, starter patterns, CLI, and crash/hang tests.

## J — Reputation

- [ ] Add provider interface, offline local database, allow/block lists, cache expiry, conflicts, mock provider, privacy controls, schema, tests, and CLI.

## K — Additional parsers

- [ ] Add bounded .NET, scripts, LNK, ZIP, OOXML/OLE, PDF, MSI/CAB, and ISO parsers with schemas, fixtures, fuzzing, and content identification.
- [ ] Publish parser `v0.2.0` only after verification.

## L — Scoring and ML

- [~] Transparent advisory heuristic score exists (`00b24b8`).
- [ ] Add category caps, correlated-signal controls, versioned configuration, and full contribution evidence.
- [ ] Add authorized dataset manifest, grouped training/evaluation, logistic baseline, bounded Rust inference, hashes/signatures, rollback, metrics, and model card.

## CLI, testing, CI, documentation, releases

- [~] `features`, `rules`, and `score` commands exist and are non-enforcing.
- [ ] Complete reputation/pattern commands, exit classes, stdout/stderr guarantees, golden/property/fuzz/performance suites.
- [ ] Pin CI actions, add audit/license/CodeQL/secret scanning/fuzz/schema drift/SBOM/attestations, and protect release keys.
- [ ] Complete required documentation, changelog, DCO commits, release artifacts, hashes, and attestations.

## Non-goals

Real-time filtering, kernel drivers, process monitoring, network interception, enforcement, quarantine, deletion, GUI, cloud dashboard, file upload, dynamic execution, sandboxing, reverse engineering, and AI enforcement remain out of scope.
