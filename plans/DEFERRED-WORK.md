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

## Scheduled reputation fuzz campaigns
- Requirement: Scheduled bounded fuzz runs and a checked-in regression corpus for the Phase J targets.
- Original phase: J7.
- Reason for deferral: Targets compile locally, but cargo-fuzz is unavailable in the current Windows environment and hosted CI has not yet produced a campaign artifact.
- Security or compatibility impact: Compile-time coverage exists; campaign-level hang, allocation, and crash evidence is still pending.
- Required future milestone: Phase J acceptance closure.
- Dependencies: Hosted CI runner, cargo-fuzz installation, safe corpus-artifact policy.
- Blocks formal acceptance: Yes, for formal J acceptance; no, for the implemented provider/store/cache behavior.
