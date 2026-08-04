# Reputation Providers

Phase J uses a provider-independent SHA-256 lookup contract. The local provider is offline-only and reports evidence states, not a final verdict. `unknown`, `unavailable`, `rate_limited`, `unauthorized`, and `provider_error` are never treated as benign. Remote providers are not implemented or enabled.
