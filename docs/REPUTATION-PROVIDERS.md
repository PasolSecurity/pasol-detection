# Reputation Providers

Phase J uses a provider-independent SHA-256 lookup contract. The local provider is offline-only and reports evidence states, not a final verdict. The supported states are `known_benign`, `known_malicious`, `suspicious`, `unknown`, `unavailable`, `rate_limited`, `unauthorized`, and `provider_error`. Unknown, unavailable, rate-limited, unauthorized, and provider-error results are never treated as benign. Conflicting active local records resolve to `suspicious`; expired or disabled records do not participate. Remote providers are not implemented or enabled.

Reports use schema `1.0.0` and preserve provider, provider version, timestamps, labels, source, and cache metadata. All lookups are hash-only and bounded. No provider may produce a final malware verdict or enforcement action.
