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
