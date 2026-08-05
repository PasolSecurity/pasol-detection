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

## DEC-J-002
### Date
2026-08-03
### Decision
Expand the active scope from J1 to the complete offline Phase J foundation (J1–J6).
### Context
The user explicitly requested implementation of the complete continuation plan after J1 activation.
### Options considered
Remain on J1 only; implement full J offline foundation; begin another phase.
### Selected option
Implement J1–J6 sequentially, preserving offline-only behavior and excluding remote providers, uploads, verdicts, and enforcement.
### Security implications
All provider failures and unknown states remain distinct; local store input is bounded and validated; no network dependency is introduced.
### Compatibility implications
New reputation schemas remain versioned independently from feature and rule schemas.
### Alternatives rejected
Remote reputation and Phase I pattern matching remain out of scope.
### Revisit conditions
Stop after Phase J acceptance and require explicit approval for the next phase.

## D-I-001
### Date
2026-08-04
### Decision
Activate Phase I I0 and use YARA-X `1.19.0` through a dedicated Pasol adapter, with production scanning deferred to a one-shot isolated worker.
### Context
G, H, and J are accepted. The approved Phase I plan selects YARA-X and requires a compatibility-only first slice before schemas, worker, CLI, or packs.
### Options considered
External YARA-X CLI; direct in-process scanning; Rust `yara-x` adapter with later worker isolation.
### Selected option
Pin `yara-x = 1.19.0`, disable default features, enable only constant folding, exact atoms, fast regexp, generated protobuf code, and the PE, hash, math, and string modules. Disable includes and reject all unapproved modules. Use a one-request-per-process worker for production scans.
### Security implications
No inspected content is executed, loaded, uploaded, or read by path. Includes, callbacks, network-capable or unnecessary modules, and environment-dependent output are prohibited. Parent hard timeouts remain mandatory because engine timeouts are advisory.
### Compatibility implications
YARA-X `1.19.0` declares Rust `1.91.0`; compatibility must be verified against the workspace MSRV and Windows before I0 is accepted. The dependency is pinned in the lockfile and upgrades require a new decision.
### Alternatives rejected
Launching an external CLI would add process and parser ambiguity; direct in-process scanning would weaken the isolation boundary; default YARA-X features would enable unnecessary modules.
### Revisit conditions
Revisit only if the MSRV/Windows compatibility spike fails, an approved security review changes the module policy, or YARA-X releases a required security fix.

## D-I-002
### Date
2026-08-04
### Decision
Implement I1 as a contract-only crate with schema version `1.0.0`, runtime validation, deterministic normalization, and explicit bounded statuses before adding signing, compilation, worker execution, or CLI behavior.
### Context
I0 compatibility is accepted under Rust 1.91 and Windows. The next approved slice must stabilize public interfaces before higher-risk engine and process-boundary code.
### Options considered
Add contracts alongside the worker; expose YARA-X types directly; establish independent Pasol-owned contracts first.
### Selected option
Use Pasol-owned serde/schemars types and checked-in JSON schemas for requests, reports, pack identity, limits, statuses, warnings, matches, and worker protocol envelopes. Keep worker envelopes contract-only in I1.
### Security implications
Unknown, timeout, worker-failure, and non-evaluated states cannot collapse into no-match. Bounds, deterministic ordering, path restrictions, and omission of raw matched bytes are enforced before later engine integration.
### Compatibility implications
Schema version `1.0.0` is independent from YARA-X versions. Breaking changes require a schema major version.
### Alternatives rejected
YARA-X internal types would couple public reports to an unstable dependency API; adding worker behavior now would combine unrelated trust and process-boundary changes.
### Revisit conditions
Revisit only for a schema compatibility decision or a proven I2/I3 requirement.

## D-I-003
### Date
2026-08-04
### Decision
Harden I1 contracts with framed payload metadata, typed scalar metadata, non-forgeable verified-pack construction, applied-limit validation, explicit status/evidence rules, and canonical source-path checks before I2.
### Context
The initial I1 slice validated reports but allowed unconstrained metadata, forged verified identities, incomplete request/response validation, and no binding between declared input identity and worker payloads.
### Options considered
Keep JSON byte arrays and permissive values; defer validation to the worker; enforce all contract invariants before worker implementation.
### Selected option
Keep raw bytes outside the JSON control envelope, bind payload length and SHA-256 in `PatternWorkerRequest`, restrict metadata to scalar values, and reject invalid paths, limits, schemas, and status combinations at the contract boundary.
### Security implications
Prevents identity/payload disagreement, output amplification, path traversal, nested metadata expansion, and uncertain states being represented as clean no-match results.
### Compatibility implications
The I1 JSON shape changes before public production release; schema remains `1.0.0` for this pre-acceptance milestone and must be frozen only after golden review.
### Alternatives rejected
Allowing arbitrary JSON metadata or treating the worker as the sole validator would expand attack surface and complicate deterministic reports.
### Revisit conditions
Revisit only if I2 framing integration requires a protocol-compatible adjustment or a schema review identifies a breaking issue.

## D-I-004
### Date
2026-08-04
### Decision
Keep verified pattern-pack identity non-forgeable at the I1 boundary and preserve exact UTF-8 rule-source bytes for hashing while accepting LF, CRLF, and tabs as ordinary source whitespace.
### Context
I1 request contracts must not allow untrusted JSON or development identities to masquerade as verified packs. YARA source commonly uses multiline LF/CRLF and tabs, but source hashing must remain byte-exact.
### Options considered
Serialize the verified wrapper; reject all controls; normalize source before hashing; or enforce proof and source policy before I2.
### Selected option
Use `PatternPackReference` in requests, keep `VerifiedPatternPack` constructible only through an internal Verified-state constructor, accept LF/CRLF/TAB, reject standalone CR/NUL/other controls, and retain original UTF-8 bytes for hashing.
### Security implications
Prevents forged trust state, ambiguous source identity, path/control injection, and manifest/source hash drift.
### Compatibility implications
The I1 schema remains `1.0.0`; the proof boundary is a Rust API restriction and source validation policy that I2 must preserve.
### Alternatives rejected
Public deserialization of verified state, permissive control-character handling, and silent line-ending normalization before hashing.
### Revisit conditions
Revisit only if a future signed-pack protocol requires an explicitly versioned source canonicalization rule.

## D-I-005
### Date
2026-08-05
### Decision
Activate I2 as the sole implementation milestone and extract reusable Ed25519 trust infrastructure into `pasol-trust`.
### Context
I0 and I1 are accepted, while pattern-pack signing and verification must be implemented without coupling `pasol-patterns` to `pasol-rules`.
### Selected option
Use `pasol-trust` as the shared dependency of rules and patterns, preserve Phase H serialized formats and behavior, and keep I3 compilation, worker, CLI, and scanning inactive.
### Security implications
One reviewed key-store and signature-verification implementation reduces divergence across artifact types.
### Compatibility implications
Existing `pasol-rules` public imports are re-exported where practical; trusted-key JSON remains compatible; pattern signatures use a distinct domain-separated payload.
### Revisit conditions
Revisit only for a documented trust-schema or algorithm migration.

## D-I-006
### Date
2026-08-05
### Decision
Hash exact stored UTF-8 source bytes and sign a domain-separated canonical pattern manifest.
### Context
Line-ending normalization before hashing would create ambiguous source identity.
### Selected option
Hash exact bytes, canonicalize only the typed manifest, and sign `PASOL\\0PATTERN-PACK\\0SIGNATURE\\0V1\\0` plus length-prefixed key ID and manifest bytes.
### Security implications
Prevents cross-protocol signature reuse, source-hash substitution, and canonicalization ambiguity.
### Compatibility implications
LF and CRLF source variants have distinct hashes; formatting changes require a new signature.
### Revisit conditions
Revisit only with a new signature schema major version.

## D-I-007
### Date
2026-08-05
### Decision
Define I3 as a separate, planning-only `pasol-pattern-compiler` milestone with proof-carrying inputs and a strict YARA-X policy.
### Context
I0–I2 are accepted, but compiler behavior must remain isolated from contracts, trust, worker execution, and scanning until explicitly activated.
### Selected option
Use a dedicated compiler crate accepting only verified or explicitly development-validated pack types; allow only `pe`, `hash`, `math`, and `string`; disable includes and relaxed regular-expression syntax; reject slow patterns, slow loops, global rules, and all compiler warnings; prohibit scanners, persistence, compiled-rule deserialization, and enforcement.
### Security implications
The proof boundary prevents raw or unverified sources from reaching compilation. The allowlist and zero-warning policy fail closed. Hard time and memory isolation is deferred to I4.
### Compatibility implications
YARA-X remains pinned at 1.19.0 with the existing restricted feature set. Compiler reports are versioned independently from pattern reports.
### Alternatives rejected
Embedding compiler logic in `pasol-patterns`, accepting raw source maps, enabling includes, ignoring modules, tolerating warnings, or loading serialized compiled rules.
### Revisit conditions
Revisit only through explicit I3 activation or a new policy/schema decision.
