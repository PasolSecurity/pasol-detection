# Acceptance checklist

## G — Feature Catalog
- [x] Runtime feature-schema validation — Evidence: `TEST-EVIDENCE.md#2026-08-03-feature-schema`; Commit `03d4f93`.
- [x] Six availability states — Evidence: `TEST-EVIDENCE.md#2026-08-03-feature-states`; Commit `588b349`.
- [x] Golden PE32/PE64/partial reports and byte-for-byte comparison — Evidence: `TEST-EVIDENCE.md#2026-08-03-phase-g-feature-goldens`.
- [x] Catalog-driven positive/negative and uncertain-state coverage — Evidence: `TEST-EVIDENCE.md#2026-08-03-phase-g-feature-goldens`.
- [x] Schema-drift validation gate — Evidence: `TEST-EVIDENCE.md#2026-08-03-schema-drift-and-starter-fixtures`.

## H — Rules Engine
- [x] Runtime pack/report schemas — Evidence: `TEST-EVIDENCE.md#2026-08-03-rule-schemas`; Commit `66b4e42`.
- [x] Generated-key tamper resistance — Evidence: `TEST-EVIDENCE.md#2026-08-03-signed-pack-tests`; Commit `a251ba2`.
- [x] Trusted-key store and lifecycle primitives — Evidence: `TEST-EVIDENCE.md#2026-08-03-key-store`; Commit `fe225e4`.
- [x] Pack signing and verification CLI — Evidence: `TEST-EVIDENCE.md#2026-08-03-pack-cli`; Commit `6df45d6`.
- [x] Golden rule reports and operator/state matrix — Evidence: `TEST-EVIDENCE.md#2026-08-03-golden-and-operator-matrix`; Commit `ff39e83`.

## I — Pattern Matching
- [x] I0 YARA-X engine decision, pinned dependency, compatibility evidence, and harmless in-memory test — Evidence: `TEST-EVIDENCE.md#2026-08-04-phase-i0-msrv-and-i1-contracts`; Commit `58e20ed`.
- [x] I1 contracts, schemas, runtime validation, deterministic serialization, bounded evidence, proof boundary, source-line-ending policy, negative matrix, and twelve deterministic goldens — Evidence: `TEST-EVIDENCE.md#2026-08-04-i1-proof-boundary-and-golden-corpus`.
- [x] I2 signed pattern-pack validation, shared trust, exact-byte source verification, hosted replay, and bounded smoke campaigns. Evidence: `TEST-EVIDENCE.md#2026-08-05-current-commit-pattern-fuzz-smoke-passed`; Commits `07546b3`, `57aa637`, `324e83e`, `0c36f03`.
- [x] I3 planning-only compiler-adapter milestone defines architecture, limits, module policy, warning policy, tests, CI, documentation, and non-goals. Evidence: `milestones/I3-COMPILER-ADAPTER.md`.
- [x] I3 activated as the sole active implementation milestone with I4, I5, K, and L inactive and I0–I2 acceptance preserved. Evidence: `CURRENT-MILESTONE.md`; `DECISIONS.md#dec-i-008`.
- [-] I2-H1 expanded pattern-pack property coverage — deferred hardening; does not qualify I2 acceptance. Evidence: `DEFERRED-WORK.md`.
- [-] I2-H2 expanded semantic fuzz corpus seeds — deferred hardening; does not qualify I2 acceptance. Evidence: `DEFERRED-WORK.md`.
- [-] I2-H3 `pasol-patterns` no-behavior-change module split — deferred hardening; does not qualify I2 acceptance. Evidence: `DEFERRED-WORK.md`.
- [ ] I3 compiler-adapter implementation and hosted acceptance.

## J — Reputation
- [x] J1-J8 provider, store, cache, CLI, goldens, property tests, fuzzing, documentation, and hosted evidence — Evidence: `TEST-EVIDENCE.md#2026-08-04-hosted-fuzz-acceptance-run`.

## K — Additional Parsers
- [ ] .NET, scripts, LNK, ZIP, Office, PDF, MSI/CAB, ISO, fixtures, fuzzing, and parser release.

## L — Scoring and ML
- [x] Initial advisory heuristic score — Evidence: `TEST-EVIDENCE.md#2026-08-03-scoring`; Commit `00b24b8`.
- [ ] Caps, correlation controls, ML baseline, data provenance, model card, metrics, and signed artifacts.

## CI and supply-chain security
- [x] Rust 1.91 MSRV workflow added for I0/I1 compatibility — Evidence: `TEST-EVIDENCE.md#2026-08-04-phase-i0-msrv-and-i1-contracts`.
- [ ] Schema drift, pinned actions, audits, CodeQL, secrets, fuzzing, SBOM, attestations, protected releases.

## Documentation, releases, governance
- [~] Architecture, security, roadmap, trust, and pattern-engine documentation.
- [ ] Complete required documentation, public release, DCO, governance, and acceptance report.
