# Acceptance checklist

## G — Feature Catalog
- [x] Runtime feature-schema validation — Evidence: `TEST-EVIDENCE.md#2026-08-03-feature-schema`; Commit `03d4f93`.
- [x] Six availability states — Evidence: `TEST-EVIDENCE.md#2026-08-03-feature-states`; Commit `588b349`.
- [x] Golden PE32/PE64/partial reports and byte-for-byte comparison.
  - Evidence: `TEST-EVIDENCE.md#2026-08-03-phase-g-feature-goldens`.
- [x] Catalog-driven positive/negative and meaningful uncertain-state coverage.
  - Evidence: `TEST-EVIDENCE.md#2026-08-03-phase-g-feature-goldens`.
- [x] Schema-drift validation gate for checked-in schemas, parser outputs, and rule goldens.
  - Evidence: `TEST-EVIDENCE.md#2026-08-03-schema-drift-and-starter-fixtures`.

## H — Rules Engine
- [x] Runtime pack/report schemas — Evidence: `TEST-EVIDENCE.md#2026-08-03-rule-schemas`; Commit `66b4e42`.
- [x] Generated-key tamper resistance — Evidence: `TEST-EVIDENCE.md#2026-08-03-signed-pack-tests`; Commit `a251ba2`.
- [x] Trusted-key store and key lifecycle primitives — Evidence: `TEST-EVIDENCE.md#2026-08-03-key-store`; Commit `fe225e4`.
- [x] Pack signing and verification CLI — Evidence: `TEST-EVIDENCE.md#2026-08-03-pack-cli`; Commit `6df45d6`.
- [x] Golden rule reports and full operator/state matrix — Evidence: `TEST-EVIDENCE.md#2026-08-03-golden-and-operator-matrix`; Commit `ff39e83`.

## I — Pattern Matching
- [ ] YARA-X worker, packs, limits, schemas, CLI, and tests.

## J — Reputation
- [ ] Offline provider, cache, mock provider, privacy, schema, CLI, and tests.

## K — Additional Parsers
- [ ] .NET, scripts, LNK, ZIP, Office, PDF, MSI/CAB, ISO, fixtures, fuzzing, and parser release.

## L — Scoring and ML
- [x] Initial advisory heuristic score — Evidence: `TEST-EVIDENCE.md#2026-08-03-scoring`; Commit `00b24b8`.
- [ ] Caps, correlation controls, ML baseline, data provenance, model card, metrics, and signed artifacts.

## CI and supply-chain security
- [ ] Schema drift, pinned actions, audits, CodeQL, secrets, fuzzing, SBOM, attestations, protected releases.

## Documentation, releases, governance
- [~] Architecture, security, roadmap, and trust docs.
- [ ] Complete required documentation, public repository release, DCO, governance, and acceptance report.
