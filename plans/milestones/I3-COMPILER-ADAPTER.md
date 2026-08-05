# I3 — YARA-X Compiler Adapter Validation

## Status

Planning specification complete. Implementation is not active and must not begin without a separate explicit approval that updates `plans/CURRENT-MILESTONE.md`.

## Objective

Convert an already validated `VerifiedPatternPack` or explicitly loaded `DevelopmentPatternPack` into bounded, deterministic, in-memory YARA-X compiled rules under a strict Pasol-owned compiler policy.

I3 validates the compiler adapter and rule-policy boundary only. It does not scan files or memory, launch a worker, expose CLI commands, persist compiled rules, or produce malware verdicts.

## Dependencies

- Phase G accepted.
- Phase H accepted.
- Phase J accepted.
- I0 accepted: YARA-X `1.19.0` pinned and verified on Rust `1.91.0` and Windows.
- I1 accepted: versioned pattern contracts, deterministic reports, bounds, proof boundaries, and golden corpus.
- I2 accepted: shared trust, signed pattern-pack validation, exact-byte source hashing, bounded bundles, fuzzing, and hosted evidence.

## Explicit non-goals

I3 must not add or expose:

- Pattern scanning of files, folders, processes, or in-memory payloads.
- `yara_x::Scanner` construction or scan calls.
- Worker-process execution, Windows Job Objects, process termination, hard wall-clock limits, or hard memory limits.
- CLI pattern commands.
- Filesystem pack discovery or directory walking.
- Compiled-rule persistence, release artifacts, or loading compiled-rule bytes.
- `Rules::deserialize` or `Rules::deserialize_from` on any input.
- Network access, uploads, telemetry, cloud services, or remote providers.
- Blocking, quarantine, deletion, remediation, enforcement, or final antivirus verdicts.
- Phase I4, I5, K, or L implementation.

## Architecture decision

Create a dedicated crate:

```text
crates/pasol-pattern-compiler/
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── adapter.rs
    ├── diagnostics.rs
    ├── error.rs
    ├── policy.rs
    └── report.rs
```

Dependency direction:

```text
pasol-trust
     ↓
pasol-patterns
     ↓
pasol-pattern-compiler
     ↓
future pasol-pattern-worker
```

Do not put YARA-X compiler implementation into `pasol-patterns`. The contracts and trust crate must remain usable without importing the engine.

## Public boundary

### Input APIs

The adapter must expose separate proof-preserving entry points:

```rust
pub fn compile_verified_pack(
    pack: &VerifiedPatternPack,
    policy: &CompilerPolicy,
) -> Result<CompiledPatternPack, PatternCompileFailure>;

pub fn compile_development_pack(
    pack: &DevelopmentPatternPack,
    policy: &CompilerPolicy,
) -> Result<CompiledPatternPack, PatternCompileFailure>;
```

Do not accept `PatternPackReference`, raw manifest JSON, raw signature JSON, arbitrary source maps, or unverified bytes.

### Successful result

```rust
pub struct CompiledPatternPack {
    rules: std::sync::Arc<yara_x::Rules>,
    report: PatternCompilerReport,
}
```

Requirements:

- No `Serialize` or `Deserialize` implementation.
- Private fields.
- No unchecked constructor.
- Created only after all I2 proof checks and all I3 compiler-policy checks pass.
- `Rules` remain in memory.
- No compiled bytes are written to disk.
- A read-only rules accessor may exist for the future worker integration, but I3 must not use it for scanning.

### Failure result

```rust
pub struct PatternCompileFailure {
    pub report: PatternCompilerReport,
    pub error: PatternCompilerError,
}
```

No partial compiled pack may escape on failure.

## Versioned compiler report

Add:

```text
schemas/pattern-compiler-report-1.0.0.schema.json
```

Suggested contract:

```rust
pub struct PatternCompilerReport {
    pub schema_version: String,
    pub adapter: PatternCompilerDescriptor,
    pub engine: PatternEngineDescriptor,
    pub policy: CompilerPolicyDescriptor,
    pub pattern_pack: PatternPackIdentity,
    pub status: PatternCompilerStatus,
    pub source_count: u32,
    pub namespace_count: u32,
    pub rule_count: u32,
    pub public_rule_count: u32,
    pub private_rule_count: u32,
    pub global_rule_count: u32,
    pub pattern_count: u32,
    pub imported_modules: Vec<String>,
    pub warnings: Vec<PatternCompilerDiagnostic>,
    pub errors: Vec<PatternCompilerDiagnostic>,
}
```

Statuses:

```text
compiled
rejected
resource_limited
unsupported_engine
internal_failure
```

Successful reports must use `compiled`, contain no errors, and contain no warnings under the initial zero-warning policy.

Rejected reports must not claim successful compilation and must not contain compiled-rule bytes.

## Determinism requirements

- Sort verified sources before compilation by namespace, then canonical path.
- Group sources by namespace deterministically.
- Use pack-relative canonical paths as YARA-X source origins.
- Sort imported modules.
- Sort normalized diagnostics by severity, code, source path, line, column, and message.
- Sort rule-derived summary information where represented.
- Disable ANSI color in diagnostics.
- Use fixed adapter and policy identifiers.
- Do not include local absolute paths, process IDs, machine names, temporary paths, current timestamps, elapsed time, memory addresses, or nondeterministic debug output in the versioned report.
- Identical pack, engine version, and policy must produce byte-identical reports on repeated runs on the same supported platform.
- Cross-platform report goldens must exclude engine-generated content that is not demonstrated to be byte-stable across Windows and Ubuntu.

## Compiler policy

### Policy identity

```text
policy_id: pasol-pattern-compiler
policy_version: 1.0.0
engine: yara-x
engine_version: 1.19.0
metadata_policy: pasol-pattern-metadata-1
limits_profile: phase-i-default
```

### Required YARA-X configuration

Create a fresh `yara_x::Compiler` for each compilation.

Configure it before adding any source:

```rust
compiler.colorize_errors(false);
compiler.errors_max_width(120);
compiler.enable_includes(false);
compiler.relaxed_re_syntax(false);
compiler.error_on_slow_pattern(true);
compiler.error_on_slow_loop(true);
compiler.max_warnings(policy.max_compiler_warnings);
```

Rules:

- Never call `add_include_dir`.
- Never enable includes.
- Never enable relaxed regular-expression syntax.
- Never call `ignore_module`.
- Never define external globals in I3.
- Never emit a WASM file.
- Never serialize compiled rules for persistence or distribution.
- Never deserialize compiled rules.
- Never construct a scanner.

The adapter must create and consume the compiler on the same thread. Do not share or cache a `Compiler` instance.

## Module policy

Use an allowlist, not a permissive denylist.

Initial allowed modules:

```text
pe
hash
math
string
```

All other modules are prohibited.

Enforcement layers:

1. Preserve the I0 Cargo feature restriction so only the approved modules are compiled into the YARA-X dependency.
2. Call `ban_module` for every known built-in module outside the allowlist that can be named under the pinned engine version.
3. Never use `ignore_module`, because silently dropping rules or imports is prohibited.
4. After a successful build, inspect `Rules::imports()` and reject the result unless every imported module belongs to the allowlist.
5. Add tests for every allowed module and representative prohibited modules.
6. Treat a newly introduced engine module as prohibited until an explicit planning decision approves it.

## Include policy

All `include` statements are errors.

The compiler receives the complete, I2-verified source set directly. No source may be fetched from the current directory, an include directory, an environment path, a network location, or another pack.

## Warning policy

Initial production and development policy: **zero compiler warnings**.

Requirements:

- Slow patterns are errors.
- Potentially slow loops are errors.
- Maximum collected warnings: 64.
- Any remaining YARA-X compiler warning causes the pack to be rejected.
- Do not disable warnings globally.
- Do not selectively suppress warning classes in I3.
- Normalize warning codes and locations into bounded Pasol diagnostics before returning.
- Unknown future warning codes fail closed as ordinary rejected warnings.
- A future warning exception requires a new decision and policy-version change.

This strict policy prevents ambiguous or low-quality rules from becoming accepted compiler output during the first adapter milestone.

## Metadata policy

Implement `pasol-pattern-metadata-1`.

Required string metadata for every public or private rule:

```text
id
title
description
category
confidence
author
license
source
```

Optional string metadata:

```text
created
modified
```

Validation rules:

- Required metadata absence is a compile error.
- Required metadata must use string values.
- Byte-string and floating-point metadata are rejected.
- Unknown metadata may be rejected under the initial policy unless explicitly listed as optional.
- `id` must be globally unique within the pack and use a documented canonical identifier format.
- Suggested ID format: lowercase dot-separated components, such as `pasol.pe.suspicious_section_marker`.
- `confidence` must be one of `low`, `medium`, or `high`.
- `created` and `modified`, when present, must be RFC 3339 timestamps.
- Metadata keys and values are bounded.
- Metadata values must not contain NUL or prohibited control characters.

Use YARA-X metadata linters for required/type checks where practical, configured to produce errors. Perform a post-build inspection as the authoritative final check.

## Rule and tag policy

- Global rules are prohibited in I3.
- Private rules are allowed but must satisfy the same metadata and bounds as public rules.
- Rule identifiers must remain valid YARA identifiers and be bounded to 128 bytes.
- The pair `(namespace, rule identifier)` must be unique.
- Metadata `id` values must be globally unique across namespaces.
- Tags must match:

```text
^[a-z0-9][a-z0-9_-]{0,63}$
```

- Maximum 32 tags per rule.
- Duplicate tags are rejected.
- Tags must be sorted in normalized evidence.

Use YARA-X rule-name and tag linters where their stable API supports the policy. Post-build inspection remains mandatory.

## Source and namespace handling

- Compile only source bytes already verified by I2.
- Preserve exact verified source bytes.
- Convert bytes to UTF-8 only through the existing verified source boundary.
- Do not normalize source line endings.
- Add sources in deterministic namespace/path order.
- Call `new_namespace` before adding the first source for each namespace.
- Add each source through `SourceCode::with_origin` using only its canonical pack-relative path.
- Never use a host filesystem path as the origin.
- Maximum namespaces: 32.
- Empty namespace values are rejected by I2 and must not be accepted here.

## Compiler limits

Create:

```rust
pub struct CompilerLimits {
    pub max_sources: u32,
    pub max_source_bytes: u64,
    pub max_namespaces: u32,
    pub max_rules: u32,
    pub max_patterns_total: u32,
    pub max_patterns_per_rule: u32,
    pub max_tags_per_rule: u32,
    pub max_metadata_per_rule: u32,
    pub max_imports: u32,
    pub max_compiler_warnings: usize,
    pub max_diagnostics: u32,
    pub max_diagnostic_message_bytes: u32,
    pub max_report_bytes: u64,
}
```

Default values:

| Limit | Default | Hard ceiling |
|---|---:|---:|
| Sources | 64 | 256 |
| Total source bytes | 4 MiB | 16 MiB |
| Namespaces | 32 | 128 |
| Rules | 2,000 | 10,000 |
| Total patterns | 16,000 | 64,000 |
| Patterns per rule | 256 | 1,024 |
| Tags per rule | 32 | 128 |
| Metadata entries per rule | 32 | 128 |
| Imports | 4 | 16 |
| Compiler warnings collected | 64 | 256 |
| Diagnostics returned | 128 | 512 |
| Diagnostic message | 4 KiB | 16 KiB |
| Compiler report | 1 MiB | 4 MiB |

Requirements:

- Validate all configured limits before compilation.
- Reuse or tighten I2 source limits; never expand a verified bundle beyond its accepted bounds.
- Use checked arithmetic for totals.
- Inspect compiled rules after `build()` and reject counts beyond configured limits.
- Bound diagnostics before serialization.
- Bound the final report by serialized byte length.
- If a post-build limit fails, discard the compiled rules and return `resource_limited`.

## Time and memory boundary

I3 does not claim hard compiler time or memory isolation.

The in-process adapter may record operational measurements in tests or logs, but versioned deterministic reports must not include them.

Until I4 is accepted:

- No CLI or service may compile user-selected packs through this adapter.
- No external untrusted source may reach the compiler.
- The adapter is a foundation component for controlled tests and future worker integration only.
- Hard wall-clock timeout, Job Object, memory cap, process termination, crash containment, and worker protocol belong to I4.

## Compiled-rule serialization policy

YARA-X `Rules::serialize` may be used only in a narrowly scoped test when necessary to measure an in-memory output size or verify engine behavior.

I3 must not:

- Persist serialized rules.
- Check compiled-rule blobs into fixtures.
- Accept compiled-rule bytes from callers.
- Deserialize compiled-rule bytes.
- Treat compiled serialization as portable across engine versions or platforms.
- Use serialized compiled bytes as the pack trust identity.

The signed canonical manifest and exact source hashes remain the authoritative artifact identity.

## Diagnostic model

Suggested types:

```rust
pub enum PatternDiagnosticSeverity {
    Warning,
    Error,
}

pub struct PatternCompilerDiagnostic {
    pub severity: PatternDiagnosticSeverity,
    pub code: String,
    pub title: String,
    pub message: String,
    pub source_path: Option<String>,
    pub line: Option<u32>,
    pub column: Option<u32>,
}
```

Requirements:

- Prefer stable engine diagnostic codes where exposed.
- Sanitize all text.
- No ANSI escape sequences.
- No absolute paths.
- No source contents or full source-line excerpts in versioned reports.
- No Rust debug formatting, backtraces, temporary filenames, or memory addresses.
- Keep only canonical pack-relative origins.
- Truncate diagnostics deterministically at configured limits.
- Preserve an explicit truncation warning or field when diagnostics are omitted.

## Error model

Suggested errors:

```rust
pub enum PatternCompilerError {
    InvalidPolicy(String),
    UnsupportedEngine(String),
    UnverifiedInput,
    IncludeForbidden,
    ModuleForbidden(String),
    CompilerRejected,
    WarningRejected,
    MetadataPolicy(String),
    GlobalRuleForbidden(String),
    DuplicateRule(String),
    DuplicateMetadataId(String),
    ResourceLimit(String),
    ReportValidation(String),
    Internal(String),
}
```

User-facing or structured errors must not reveal machine-specific paths or source content.

## Implementation slices after explicit approval

### I3.1 — Crate and report contracts

- Add `pasol-pattern-compiler`.
- Add policy, limit, report, diagnostic, error, failure, and compiled proof types.
- Add `pattern-compiler-report-1.0.0.schema.json`.
- Add runtime schema validation.
- Add deterministic normalization and report-size checks.
- Do not call YARA-X yet except in the accepted compatibility test.

### I3.2 — Strict compiler construction

- Construct a fresh compiler per request.
- Apply include, regex, warning, slow-pattern, slow-loop, module, and diagnostic settings.
- Add metadata and tag linters.
- Add no source scanning and no worker behavior.

### I3.3 — Deterministic source ingestion

- Accept proof-carrying verified or development packs only.
- Sort and group sources deterministically.
- Create namespaces explicitly.
- Add source origins using canonical pack-relative paths.
- Normalize compile errors into Pasol diagnostics.

### I3.4 — Post-build policy audit

- Inspect imports, rules, namespaces, private/global state, tags, metadata, and patterns.
- Enforce limits and uniqueness.
- Reject global rules, prohibited modules, warnings, invalid metadata, and limit overflow.
- Construct `CompiledPatternPack` only after the audit succeeds.

### I3.5 — Deterministic reports and goldens

Add harmless report goldens for:

```text
compiled-minimal.json
compiled-multi-source.json
rejected-include.json
rejected-module.json
rejected-warning.json
rejected-metadata.json
rejected-slow-pattern.json
rejected-slow-loop.json
rejected-resource-limit.json
```

Do not add compiled-rule binary goldens.

### I3.6 — Adversarial and property coverage

Add the complete test matrix below.

### I3.7 — Fuzzing, CI, and documentation

- Add bounded compiler fuzz targets.
- Add harmless corpus seeds.
- Add Rust 1.91 Windows/Ubuntu CI.
- Add hosted Ubuntu bounded compiler smoke campaigns.
- Add compiler policy, report, privacy, and threat-model documentation.

### I3.8 — Hosted evidence and formal closure

- Record all hosted runs and results.
- Reconcile every I3 acceptance item.
- Mark I3 accepted only after all gates pass.
- Clear the active implementation milestone.
- Leave I4 inactive.

## Required positive tests

- Valid minimal verified pack compiles.
- Valid multi-source verified pack compiles.
- Explicit development pack compiles through the development entry point.
- Same namespace across multiple sources works deterministically.
- Multiple namespaces compile in deterministic order.
- Every allowed module compiles in a harmless fixture.
- Private helper rule compiles under the metadata policy.
- Tags and metadata are summarized deterministically.
- Identical pack and policy produce byte-identical reports.
- Source-map insertion order does not change the report.
- Pack signing-key state does not alter compiler semantics except reported trust state.

## Required rejection tests

### Proof boundary

- `PatternPackReference` cannot be compiled.
- Raw source map cannot be compiled.
- Invalid or forged trust state cannot produce a compiled result.
- Development pack cannot enter the verified entry point.

### Includes and modules

- Include statement rejected.
- Representative banned module rejected.
- Unknown module rejected.
- Ignored-module behavior is never enabled.
- Post-build import audit rejects any non-allowlisted import.

### Syntax and compatibility

- Syntax error rejected.
- Invalid UTF-8 cannot reach the adapter through proof types.
- Relaxed regular-expression-only syntax rejected.
- Unsupported engine or engine version rejected.

### Performance policy

- Slow pattern rejected.
- Potentially slow loop rejected.
- Excessive loop-iteration warning rejected.
- Warning-producing unused identifier rejected.
- Any compiler warning rejects the pack.

### Metadata and tags

- Missing required metadata rejected.
- Wrong metadata type rejected.
- Byte metadata rejected.
- Float metadata rejected.
- Invalid confidence rejected.
- Invalid timestamp rejected.
- Unknown metadata rejected under policy version 1.0.0.
- Duplicate global metadata ID rejected.
- Invalid tag rejected.
- Duplicate tag rejected.
- Excessive tags rejected.

### Rule structure

- Global rule rejected.
- Duplicate `(namespace, rule identifier)` rejected.
- Excessive rule count rejected.
- Excessive total patterns rejected.
- Excessive patterns per rule rejected.
- Excessive metadata entries rejected.
- Excessive namespace count rejected.
- Excessive import count rejected.

### Diagnostics and reports

- Diagnostics contain only canonical relative source origins.
- Diagnostics contain no ANSI escapes.
- Diagnostics contain no absolute path.
- Diagnostics contain no raw source-line excerpt in the serialized report.
- Diagnostic count truncation is deterministic.
- Oversized diagnostic message is bounded.
- Oversized report is rejected.
- Failure never returns `CompiledPatternPack`.

## Property tests

- Source insertion order does not change a successful report.
- Namespace insertion order does not change a successful report.
- Diagnostic ordering is stable.
- Reducing a limit cannot make a previously oversized pack valid.
- A compiled result always has status `compiled` and no errors or warnings.
- A rejected result never contains a compiled proof object.
- Every imported module in a successful result belongs to the allowlist.
- Every metadata ID in a successful result is unique.
- Every successful report validates against its schema.
- Serialization, deserialization, and reserialization of reports are byte-stable.

## Fuzz targets

Add:

```text
pattern_compiler_source
pattern_compiler_pack
```

### `pattern_compiler_source`

- Maximum generated source: 64 KiB.
- Compile only through a development pack constructed by validated test helpers.
- Strict compiler policy enabled.
- No filesystem writes or network.
- Invariants: no panic, no successful warning-bearing report, no prohibited import in success.

### `pattern_compiler_pack`

- Maximum 8 sources.
- Maximum 256 KiB aggregate source bytes.
- Generated manifests and sources remain bounded.
- Invariants: no panic, no proof-boundary bypass, no global rule in success, all report bounds hold.

Hosted campaigns must use failure-only artifact upload and harmless corpus seeds.

## CI requirements

Under Rust `1.91.0` on Windows and Ubuntu:

```text
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo test -p pasol-pattern-compiler --all-features
cargo test -p pasol-patterns --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

Additional gates:

- Compiler report schema drift.
- Golden report regeneration.
- Fuzz-target compilation.
- Checked-in corpus replay.
- Bounded hosted Ubuntu compiler fuzz smoke campaigns.
- Pinned GitHub Actions and read-only permissions.

## Documentation requirements

Add:

```text
docs/PATTERN-COMPILER.md
docs/PATTERN-COMPILER-POLICY.md
docs/PATTERN-COMPILER-THREAT-MODEL.md
docs/adr/ADR-PATTERN-COMPILER-BOUNDARY.md
```

Documentation must explain:

- Proof-carrying inputs.
- Separate compiler crate.
- Module allowlist.
- Includes disabled.
- Strict regular-expression syntax.
- Zero-warning policy.
- Metadata and tag policy.
- No global rules.
- Resource limits.
- Deterministic diagnostics.
- No scanning in I3.
- No compiled-rule persistence or deserialization.
- Lack of hard in-process time/memory isolation until I4.
- Why worker execution remains mandatory before external use.

## Risks and mitigations

### In-process compiler resource exhaustion

- Severity: High.
- Mitigation: proof-carrying bounded inputs, strict slow-pattern/loop rejection, no external invocation, hosted fuzzing, and mandatory I4 worker isolation before CLI use.

### Engine API or diagnostic drift

- Severity: Medium.
- Mitigation: exact YARA-X version pin, Pasol-owned report types, schema and golden tests, and explicit upgrade decisions.

### Warning-policy over-rejection

- Severity: Medium.
- Mitigation: initial zero-warning fail-closed policy. Any exception requires policy-version change and evidence.

### Module-policy drift

- Severity: High.
- Mitigation: Cargo feature restriction, explicit bans, post-build import allowlist audit, and tests for allowed/prohibited modules.

### Compiled-rule blob misuse

- Severity: High.
- Mitigation: no persistence, no binary goldens, no deserialization API, no artifact loading, and source/manifest identity remains authoritative.

### Diagnostic information leakage

- Severity: Medium.
- Mitigation: canonical origins, sanitized bounded messages, no source excerpts, no absolute paths, and deterministic reports.

## I3 acceptance gate

I3 may be marked accepted only when all items below pass.

### Planning and scope

- [ ] I3 implementation was explicitly activated after this plan was approved.
- [ ] I3 remained the sole active implementation milestone.
- [ ] I4, I5, K, and L remained inactive.
- [ ] No scanning, worker execution, CLI, uploads, verdicts, or enforcement were added.

### Architecture

- [ ] `pasol-pattern-compiler` exists as a separate crate.
- [ ] It depends on `pasol-patterns`, not the reverse.
- [ ] Proof-carrying verified/development entry points are separate.
- [ ] No raw/unverified compilation entry point exists.
- [ ] `CompiledPatternPack` is non-serializable and non-forgeable.

### Compiler policy

- [ ] Includes disabled.
- [ ] Relaxed regular-expression syntax disabled.
- [ ] Slow patterns rejected.
- [ ] Slow loops rejected.
- [ ] Zero-warning policy enforced.
- [ ] No ignored modules.
- [ ] Allowed module set is exactly `pe`, `hash`, `math`, and `string`.
- [ ] Post-build import audit enforced.
- [ ] No external globals.
- [ ] No scanner creation.

### Rule policy

- [ ] Metadata policy implemented.
- [ ] Tag policy implemented.
- [ ] Global rules rejected.
- [ ] Private rules bounded and validated.
- [ ] Rule and metadata IDs unique.
- [ ] All rule/pattern/tag/metadata/import limits enforced.

### Diagnostics and reports

- [ ] Compiler report schema `1.0.0` checked in.
- [ ] Runtime schema validation passes.
- [ ] Reports normalize deterministically.
- [ ] Diagnostics are bounded and sanitized.
- [ ] No machine-specific or raw-source data appears in reports.
- [ ] Golden reports regenerate byte-for-byte.

### Compiled-rule safety

- [ ] No compiled-rule persistence.
- [ ] No compiled-rule binary fixtures.
- [ ] No `Rules::deserialize` use.
- [ ] No third-party compiled bytes accepted.
- [ ] No portable compiled-artifact claim made.

### Tests and CI

- [ ] Positive compiler tests pass.
- [ ] Complete rejection matrix passes.
- [ ] Property tests pass.
- [ ] Fuzz targets compile.
- [ ] Corpus replay passes.
- [ ] Hosted bounded smoke campaigns pass.
- [ ] Windows Rust 1.91 passes.
- [ ] Ubuntu Rust 1.91 passes.
- [ ] Workspace tests pass.
- [ ] Formatting passes.
- [ ] Clippy with warnings denied passes.
- [ ] Schema drift passes.
- [ ] Repository is clean.

### Documentation and evidence

- [ ] Compiler documentation complete.
- [ ] Policy documentation complete.
- [ ] Threat model complete.
- [ ] ADR complete.
- [ ] Commands, counts, commits, hosted links, and outcomes recorded.
- [ ] Remaining limitations and risks remain visible.

## Required planning-system updates

When adding this file to the repository, make only planning-file changes.

### `plans/CURRENT-MILESTONE.md`

Keep:

```text
Milestone:
No active implementation milestone
```

Update the scope to state:

- I3 planning specification is complete.
- I3 implementation is not active.
- Only `plans/` may change.
- The next action is explicit approval to activate I3 implementation.

Suggested next exact action:

> Explicitly approve I3 implementation. Then make I3 the sole active implementation milestone before modifying Rust code, schemas, tests, fixtures, CI, or non-planning documentation.

### `plans/milestones/I-PATTERN-MATCHING.md`

Add:

```text
- [x] I3 detailed compiler-adapter planning specification.
- [ ] I3 compiler-adapter implementation and acceptance.
```

Remove any duplicate legacy aggregate checklist item that conflicts with the numbered I0–I9 structure.

### `plans/ACCEPTANCE-CHECKLIST.md`

Add:

```text
- [x] I3 planning-only compiler-adapter milestone defines architecture, limits, module policy, warning policy, tests, CI, documentation, and non-goals.
- [ ] I3 compiler-adapter implementation and hosted acceptance.
```

### `plans/DECISIONS.md`

Add a decision recording:

- Separate `pasol-pattern-compiler` crate.
- Proof-carrying inputs only.
- Allowed modules: `pe`, `hash`, `math`, `string`.
- Includes and relaxed regexp syntax disabled.
- Zero-warning policy.
- Global rules prohibited.
- No scanner, persistence, or compiled-rule deserialization.
- Hard time/memory isolation deferred to I4.

### `plans/RISKS-AND-BLOCKERS.md`

Add the I3 risks listed above and keep them open until evidence resolves them.

### `plans/PROGRESS-LOG.md`

Record a planning-only entry with:

- No production code changed.
- I3 implementation remains unauthorized.
- Exact milestone file and planning files updated.
- Next action is explicit implementation approval.

## Planning-only completion state

This file defines I3 but does not authorize production-code changes.

The next exact action after this planning commit is:

> Obtain explicit approval to activate I3 implementation. Then update `plans/CURRENT-MILESTONE.md` to make I3 the sole active implementation milestone before modifying Rust code, schemas, tests, fixtures, CI, or documentation outside `plans/`.
