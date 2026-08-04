# Reputation Threat Model

Threats include corrupted or oversized stores, duplicate and conflicting records, expired entries, schema downgrade, output amplification, and malicious labels or reasons. Runtime schema validation, bounded arrays and strings, expiration filtering, atomic writes, and deterministic conflict handling mitigate these risks. Windows ACL hardening remains a documented limitation.
