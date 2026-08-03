# K — Additional Parsers
## Objective
Bounded factual parsing beyond PE metadata.
## Inputs
Content-identified files.
## Outputs
Normalized parser reports and schemas.
## Interfaces
Shared parser contract and isolated CLI worker.
## Schemas
Per-format schemas pending.
## Security requirements
No active content execution, bounded arithmetic, archive traversal limits.
## Implementation checklist
- [ ] .NET, scripts, LNK, ZIP/Office, PDF, MSI/CAB, ISO.
- [ ] Fixtures, fuzzing, schemas, parser release.
## Test checklist
- [ ] Valid, malformed, boundary, extension-independent tests.
## Documentation checklist
- [ ] Adding-a-parser and format docs.
## Acceptance criteria
Every listed parser is bounded, tested, and schema-valid.
## Current status
Not started.
## Completed commits
None.
## Remaining work
Entire phase.
