![PasolSecurity](assets/pasol-security-readme-banner.png)

# PasolSecurity Detection Foundation

![PasolSecurity avatar](assets/pasol-security-avatar-512.png)

This repository is the Stage 2 detection workspace. The first milestone is implemented and reviewable: versioned feature reports, deterministic PE extraction, bounded declarative rules, a starter pack, and an advisory heuristic score.

## Current milestone

- G: feature SDK, schema `1.0.0`, deterministic PE extractor, evidence/provenance, partial/unknown/unsupported states.
- H foundation: JSON rule packs, bounded expression evaluator, missing-feature `not_evaluated` behavior, explanations and evidence.
- L foundation: capped, transparent advisory static score.

Pattern worker/signing, local reputation, additional parsers, and the reproducible ML baseline remain separate follow-on milestones. They are not represented as complete here.

## Windows validation

On Windows with Rust 1.91 or newer:

```text
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
pasol-lab features PARSER_REPORT.json --format json
pasol-lab rules FEATURE_REPORT.json rule-packs/pasol-starter.json
pasol-lab score FEATURE_REPORT.json
```

The CLI only emits evidence and advisory scores. It does not execute, upload, block, delete, or quarantine files.

Stage 2 converts factual reports from [pasol-parser](https://github.com/PasolSecurity/pasol-parser) into versioned, explainable security evidence.

Milestone G currently provides the shared detection SDK, schema `1.0.0`, deterministic PE feature extraction, and the `pasol-lab features` development command. It does not execute, block, delete, quarantine, upload, or issue a final malware verdict.

Build with Rust 1.91 or newer. The parser repository remains independently compatible with Rust 1.85.
