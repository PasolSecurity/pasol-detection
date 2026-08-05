# Pattern-Pack Trust

Pattern signatures use the shared `pasol-trust` key store and detached Ed25519 signatures over a canonical manifest digest. The signing message is domain-separated with `PASOL\0PATTERN-PACK\0SIGNATURE\0V1\0`, the key identifier, and canonical manifest bytes. Active and retired keys may verify; revoked and unknown keys fail. Private keys never appear in the store or repository.

A valid signature proves publisher identity and content integrity only. It does not prove rule quality, safety, efficiency, or accuracy. Online revocation, transparency logs, rollback prevention, and production key environments remain future work.
