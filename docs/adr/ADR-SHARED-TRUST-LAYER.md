# ADR: Shared Trust Layer

Use `pasol-trust` for trusted-key storage and Ed25519 verification. `pasol-rules` and `pasol-patterns` depend on it; patterns never depend on rules. Existing Phase H JSON types and behavior remain compatible through re-exports.
