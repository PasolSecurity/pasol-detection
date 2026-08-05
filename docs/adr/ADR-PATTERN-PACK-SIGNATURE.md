# ADR: Pattern-Pack Signature

Pattern packs use a detached Ed25519 signature over a deterministic canonical manifest digest and a pattern-specific domain-separated message. Source hashes cover exact stored bytes. This prevents cross-protocol reuse and preserves provenance without introducing compilation or scanning into I2.
