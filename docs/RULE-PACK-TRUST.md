# Rule-pack trust lifecycle

Production rule packs are verified with an Ed25519 public key identified by a stable `key_id`. The signed payload is the canonical JSON rule pack; its SHA-256 digest is recorded as `manifest_sha256`. Unknown keys, invalid encodings, changed payloads, and changed manifests are rejected.

Unsigned packs may be loaded only through the explicitly named development API. Private signing keys are never stored in the trusted-key store. A deployment should keep trusted public keys in a protected, administrator-managed store, add a replacement key before rotation, and remove a compromised key immediately. Key revocation and release-environment policy remain deployment responsibilities; no private key is checked into this repository.
