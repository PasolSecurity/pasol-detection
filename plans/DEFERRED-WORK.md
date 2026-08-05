# Deferred work

## Pattern matching
- Requirement: YARA-X worker and signed pattern packs.
- Original phase: I.
- Reason for deferral: G/H trust and validation boundary is being completed first.
- Security or compatibility impact: No pattern evidence is currently produced.
- Required future milestone: I.
- Dependencies: Stable report and trust schemas.
- Blocks formal acceptance: Yes, for full Stage 2; no, for G/H.

## Reputation, parsers, and ML
- Requirement: J, K, and L machine-learning work.
- Original phase: J/K/L.
- Reason for deferral: Not yet selected as current milestone.
- Security or compatibility impact: Capabilities are absent, not silently represented as complete.
- Required future milestone: J, K, or L respectively.
- Dependencies: Approved providers, parser adapters, authorized corpus.
- Blocks formal acceptance: Yes, for full Stage 2.

## I2-H1 — Expanded pattern-pack property coverage
- Requirement: Property-test coverage for the full invariant set recorded in the I2 specification, including revoked-key rejection, unknown-key rejection, limit monotonicity, signature-message key-ID binding, manifest-field mutation invalidation, per-byte source mutation failure, normalized-path duplicate rejection, case-insensitive collision rejection, verified/development state invariants, and absence of platform path separators in canonical JSON.
- Original phase: I2.
- Reason for deferral: I2 shipped a single `proptest!` block covering canonical-digest independence from source order. The remaining invariants are covered by deterministic unit and adversarial tests rather than by generated properties, so the behavior is verified but the generative breadth is narrower than specified.
- Security or compatibility impact: None known to current behavior. All listed invariants have example-based coverage and hosted fuzz evidence; the gap is reduced probability of discovering unanticipated counterexamples, not a known unverified invariant.
- Required future milestone: I2 hardening slice, schedulable independently of I3.
- Dependencies: Existing `proptest` workspace dependency and the accepted I2 verification API.
- Blocks formal acceptance: No. I2 is accepted at the signed pattern-pack foundation level; this expands assurance depth without altering accepted behavior.

## I2-H2 — Expanded semantic fuzz corpus seeds
- Requirement: Harmless deterministic corpus seeds for the semantic cases named in the I2 specification, including traversal path, duplicate path, case-fold collision, missing source, source-hash mismatch, unknown key, and revoked key, across the three pattern-pack fuzz targets.
- Original phase: I2.
- Reason for deferral: The accepted corpus contains three seeds — `pattern_pack_manifest/seed-minimal.json`, `pattern_pack_signature/seed-invalid.json`, and `pattern_pack_bundle_verify/seed-empty.bin` — which exercise entry points but not the semantic rejection paths.
- Security or compatibility impact: Bounded hosted smoke campaigns reached 1,512,812, 436,532, and 302,618 executions with no crash, timeout, or invariant failure, so coverage is not absent; richer seeds would let campaigns reach semantic rejection branches faster rather than relying on random discovery.
- Required future milestone: I2 hardening slice, schedulable independently of I3.
- Dependencies: Existing `pattern-pack-fuzz.yml` workflow and checked-in fixtures.
- Blocks formal acceptance: No.

## I2-H3 — `pasol-patterns` module split
- Requirement: A no-behavior-change split of `crates/pasol-patterns/src/lib.rs` into the specified module structure covering contracts, signature, verifier, development, limits, canonicalization, and error concerns, alongside the existing `manifest.rs`.
- Original phase: I2.
- Reason for deferral: I2 shipped `lib.rs` at 820 lines plus `manifest.rs` at 476 lines rather than the specified eight-module layout. The structure is a maintainability concern, not a correctness or security one.
- Security or compatibility impact: None. This must be a pure refactor with no public API change, no behavior change, and no golden, schema, or signature-payload change.
- Required future milestone: I2 hardening slice. Must not be performed during an active I3 implementation slice, so that compiler-adapter review remains separable from pattern-crate restructuring.
- Dependencies: A green I2 test baseline to diff against before and after the split.
- Blocks formal acceptance: No.

## Scheduled reputation fuzz campaigns
- Requirement: Scheduled bounded fuzz runs and a checked-in regression corpus for the Phase J targets.
- Original phase: J7.
- Reason for deferral: Targets compile locally, but cargo-fuzz is unavailable in the current Windows environment and hosted CI has not yet produced a campaign artifact.
- Security or compatibility impact: Compile-time coverage exists; campaign-level hang, allocation, and crash evidence is still pending.
- Required future milestone: Phase J acceptance closure.
- Dependencies: Hosted CI runner, cargo-fuzz installation, safe corpus-artifact policy.
- Blocks formal acceptance: Yes, for formal J acceptance; no, for the implemented provider/store/cache behavior.
