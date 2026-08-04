# Decisions

## D-001
### Date
2026-08-03
### Decision
Keep parser facts and detection interpretation in separate repositories.
### Context
Avoid coupling malware interpretation to format parsers.
### Options considered
Combine all logic; separate parser and detection repositories.
### Selected option
Separate repositories and versioned JSON reports.
### Security implications
Smaller parser trust surface and explicit evidence boundary.
### Compatibility implications
Detection consumes stable schemas rather than private parser internals.
### Alternatives rejected
Embedding scoring or reputation in PE parsing.
### Revisit conditions
Only if a shared schema crate is needed without reversing dependency direction.

## D-002
### Date
2026-08-03
### Decision
Use Ed25519 signatures over canonical serialized rule packs plus SHA-256 manifests.
### Context
Rule packs must reject tampering and unknown keys.
### Options considered
Unsigned local files; symmetric MAC; Ed25519 public-key signatures.
### Selected option
Ed25519 with trusted public-key store.
### Security implications
Private keys stay outside the repository; revoked/unknown keys fail.
### Compatibility implications
Signed envelope is versioned independently from rule schema.
### Alternatives rejected
Runtime code or embedded scripts.
### Revisit conditions
Only for a documented key-management or algorithm migration.
## DEC-J-001
### Date
2026-08-03
### Decision
Activate Phase J1 for offline reputation contracts and schemas; keep Phase I deferred.
### Context
Phases G and H are accepted at the Stage 2 foundation level. The continuation plan explicitly approves J as the next candidate and restricts the first slice to provider-independent types and schemas.
### Options considered
Begin J1; begin pattern matching; begin the full J phase; leave the project idle.
### Selected option
Begin J1 only, with no network access, remote provider, upload, verdict, or enforcement behavior.
### Security implications
The reputation layer must preserve unknown, unavailable, rate-limited, unauthorized, and provider-error states without converting them to benign results.
### Compatibility implications
J1 introduces versioned reputation schemas independently from the accepted feature and rule schemas.
### Alternatives rejected
Pattern matching remains deferred; full local-provider and CLI work waits for J1 contracts.
### Revisit conditions
Revisit when J1 acceptance evidence is complete or if the approved milestone changes.
