# Pattern Packs

I2 validates in-memory YARA-X pattern bundles. A pack contains a versioned manifest, optional detached signature, and portable `.yar`/`.yara` sources. Source hashes cover exact stored UTF-8 bytes; LF and CRLF variants therefore have different identities. I2 validates bounds, paths, namespaces, engine requirement `yara-x 1.19.0`, and approved `phase-i-default`/`pasol-pattern-metadata-1` policies. It does not compile or scan rules.

Production packs require a trusted Ed25519 signature. Development packs are a separate explicit mode and are never promoted to verified status.
