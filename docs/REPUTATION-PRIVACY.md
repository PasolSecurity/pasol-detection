# Reputation Privacy

Phase J runs offline. Hashes, files, paths, credentials, and filenames are not uploaded. The local provider reads only the configured local store; no network client or file-submission path exists. Normalized reports contain provider evidence only and omit local paths. The persistent cache is local and keyed by provider, provider version, query type, hash, and source-store revision.

CLI exit classes are stable: `0` success (including unknown), `3` filesystem/I/O failure, `4` invalid input/schema/store/cache, and `5` resource limit. In JSON mode, failures are schema-valid `reputation-cli-error-1.0.0` documents on stderr; successful JSON remains on stdout. Per-user file permissions and Windows ACL hardening depend on the host configuration and remain a documented limitation. Any future remote provider requires separate approval, credentials handling, and explicit privacy documentation.
