# ADR: YARA-X Pattern Engine

## Status

Accepted for Phase I compatibility work; production pattern scanning remains gated on later milestones.

## Decision

Use the Rust `yara-x` crate version `1.19.0` through a Pasol adapter. Pin the exact version in the workspace lockfile and do not accept upgrades without a compatibility and security review.

The first compatibility build disables default features and enables only:

- `constant-folding`
- `exact-atoms`
- `fast-regexp`
- `generate-proto-code`
- `pe-module`
- `hash-module`
- `math-module`
- `string-module`

Includes, external callbacks, arbitrary source paths, and unapproved modules are prohibited. The initial approved module set is `pe`, `hash`, `math`, and `string`.

## Context

Phase I needs bounded, explainable static pattern evidence on Windows and Linux. YARA-X provides a Rust API, compiler controls, scanner controls, namespaces, warnings, and match limits. Its published `1.19.0` crate declares Rust `1.91.0` and is licensed BSD-3-Clause.

## Isolation decision

The public API will not call YARA-X directly from the CLI or the main detection process. Later I4 work will use a one-request-per-process worker. The parent will enforce a hard wall-clock deadline and terminate the worker because the engine scan timeout is not a sufficient process boundary.

## Security policy

Inspected bytes are passed through bounded IPC; inspected paths are never given to the worker. The worker performs no network access, file writes, shell execution, child-process creation, or active-content execution. Pattern matches remain advisory evidence and never become a verdict or enforcement action.

## Alternatives rejected

- External YARA-X CLI: adds executable-discovery, argument, output-parsing, and version-coupling risks.
- Direct in-process scanning: weakens crash and resource isolation.
- YARA-X default features: enables unnecessary modules and expands the trust surface.

## Consequences

The selected feature set is smaller and more deterministic, but later requirements must be implemented explicitly rather than relying on optional YARA-X modules. Compiled-rule caches are version-bound and are not portable across arbitrary engine versions.

## Revisit conditions

Revisit only after an MSRV or Windows compatibility failure, a security review finding, a required YARA-X security release, or an approved module-policy change.
