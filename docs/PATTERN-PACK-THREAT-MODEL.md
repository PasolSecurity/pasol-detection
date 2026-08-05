# Pattern-Pack Threat Model

The I2 boundary addresses manifest and source tampering, signature substitution, key-ID substitution, revoked/unknown keys, path traversal and Windows collisions, oversized sources, malformed JSON, canonicalization ambiguity, and cross-protocol signature reuse. Exact source hashes and bounded arithmetic protect the source chain.

Limitations: malicious-but-valid signed rules remain possible; compromised publisher keys require rotation/revocation; rollback protection is not implemented; retired-key verification is not time-bounded; I2 does not compile, sandbox, execute, upload, or scan rules. Worker isolation belongs to I4.
