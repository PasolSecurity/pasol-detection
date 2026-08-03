# H — Rules Engine
## Objective
Evaluate bounded declarative rules and authenticate distributable packs.
## Inputs
Feature reports and rule packs.
## Outputs
Rule reports schema `1.0.0`.
## Interfaces
Rule evaluator, signed-pack verifier, key store, lab CLI.
## Schemas
Rule-pack and rule-report schemas.
## Security requirements
No arbitrary code; depth, count, output, and evidence limits; unknown/truncated become not evaluated.
## Implementation checklist
- [x] Evaluator and budgets — `66b4e42`.
- [x] Trust tests — `a251ba2`.
- [x] Key store primitives — `fe225e4`.
- [ ] Pack sign/verify CLI and golden reports.
## Test checklist
- [x] Generated-key tamper cases.
- [ ] Full operator/state matrix and CLI integration.
## Documentation checklist
- [x] Trust lifecycle documentation — `a251ba2`.
## Acceptance criteria
All mandatory checklist items must be verified.
## Current status
Core and trust library verified; operational tooling pending.
## Completed commits
`00b24b8`, `588b349`, `03d4f93`, `66b4e42`, `a251ba2`, `fe225e4`.
## Remaining work
Pack sign/verify, golden reports, matrix, CI drift checks.
