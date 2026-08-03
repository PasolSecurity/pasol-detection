# L — Scoring and ML
## Objective
Advisory explainable static scoring and reproducible ML research baseline.
## Inputs
Feature, rule, pattern, and reputation evidence.
## Outputs
Score schema `1.0.0`, model artifacts and reports.
## Interfaces
Static scorer, bounded Rust inference, training/evaluation tooling.
## Schemas
Score schema and model artifact schema pending.
## Security requirements
Advisory only; signed/hash-verified models; no enforcement.
## Implementation checklist
- [~] Initial heuristic scorer — `00b24b8`.
- [ ] Caps, correlation controls, dataset manifest, logistic model, model card.
## Test checklist
- [ ] Contributions, metrics, determinism, compatibility, rollback, fuzz tests.
## Documentation checklist
- [ ] Static scoring and ML methodology docs.
## Acceptance criteria
Advisory behavior and reproducible evidence verified.
## Current status
Heuristic baseline only.
## Completed commits
`00b24b8`.
## Remaining work
Scoring hardening and all ML work.
