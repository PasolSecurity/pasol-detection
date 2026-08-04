# G — Feature Catalog
## Objective
Produce deterministic schema-valid features with evidence and provenance.
## Inputs
Versioned parser reports.
## Outputs
Feature report schema `1.0.0`.
## Interfaces
`FeatureExtractor`, `PeFeatureExtractor`, `pasol-lab features`.
## Schemas
`schemas/feature-report-v1.schema.json`.
## Security requirements
No execution; preserve unknown/truncated/unsupported distinctions.
## Implementation checklist
- [x] SDK and PE extractor — `588b349`.
- [x] Runtime validation — `03d4f93`.
- [ ] Golden reports and complete catalog coverage.
## Test checklist
- [x] Six-state serialization and malformed input.
- [ ] Per-feature positive/negative and golden tests.
## Documentation checklist
- [~] Feature catalog and plan evidence.
## Acceptance criteria
All mandatory checklist items must be verified.
## Current status
Functionally complete; golden outputs and catalog-wide acceptance evidence pending.
## Completed commits
`00b24b8`, `588b349`, `03d4f93`.
## Remaining work
Checked-in PE32/PE64/partial goldens, byte-for-byte regeneration tests, and comprehensive per-feature positive/negative/unavailable/truncated coverage.
