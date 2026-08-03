# Feature Catalog

Feature identifiers are lowercase and namespaced. Feature values describe parser observations; they never express a malware verdict.

Every feature has an availability state: `present`, `absent`, `unknown`, `truncated`, `not_applicable`, or `unsupported`. `unknown` and `truncated` are never converted to `absent`.

Milestone G currently covers file identity, parser status, PE header facts, section permissions and entropy, import/export/resource counts, debug presence, version presence, and certificate-table facts. Evidence paths are JSON Pointers into the parser report. Feature reports are sorted by identifier and are deterministic for a fixed parser report.
