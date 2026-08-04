# Reputation Threat Model

Threats include corrupted or oversized stores and caches, duplicate and conflicting records, expired entries, schema downgrade, output amplification, malicious labels or reasons, cache poisoning, and accidental disclosure through diagnostics. Runtime schema validation, 8 MiB store/cache input bounds, 10,000-record limits, bounded arrays and strings, expiration filtering, provider/version/source-revision cache keys, atomic writes, transactional imports, and deterministic conflict handling mitigate these risks.

Unknown and unavailable evidence is never converted to benign. The cache does not cache unauthorized results and temporary failures are never rewritten as `known_benign`. No network, upload, execution, verdict, blocking, or quarantine behavior exists in Phase J. Windows ACL hardening remains a documented limitation; deployments must restrict store and cache files to the intended user or service account.
