# Local Reputation Store

The versioned JSON store (`local-reputation-store-1.0.0`) contains bounded, schema-validated entries. The input limit is 8 MiB and the record limit is 10,000. Labels and reasons are schema-bounded. Updates are written atomically and reopened and validated before success. Expired or disabled entries are ignored; conflicting active entries produce `suspicious` evidence, deterministically and independently of record order. Corrupt stores, unsupported states, invalid hashes, invalid timestamps, and unsupported schema versions are rejected.

Imports are transactional: the candidate store is fully validated before replacement, and exact duplicate records are rejected without modifying the existing store. Exports use deterministic ordering and the same atomic persistence path. Recovery from corruption is to restore a previously trusted export; the implementation never silently treats a corrupt store as empty.
