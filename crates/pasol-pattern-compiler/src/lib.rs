//! Bounded, deterministic YARA-X compiler adapter for verified pattern packs.
//!
//! This crate converts proof-carrying pattern packs into in-memory compiled
//! rules under a strict Pasol-owned policy. It never scans files or memory,
//! never constructs a scanner, never launches a worker, never persists or
//! deserializes compiled rules, and never produces a verdict.
//!
//! # Slice status
//!
//! I3.1 establishes the contracts only: policy, limits, report, diagnostics,
//! errors, and the compiled proof boundary. The compiler entry points arrive in
//! I3.2 through I3.4.
//!
//! # Isolation boundary
//!
//! I3 makes no hard in-process time or memory guarantee. Wall-clock timeouts,
//! memory caps, and crash containment belong to the I4 worker milestone. Until
//! I4 is accepted, no CLI or service may drive this adapter with externally
//! selected packs.

#![forbid(unsafe_code)]

pub mod diagnostics;
pub mod error;
pub mod policy;
pub mod report;

pub use diagnostics::{DiagnosticOrigin, PatternCompilerDiagnostic, PatternDiagnosticSeverity};
pub use error::PatternCompilerError;
pub use policy::{CompilerLimits, CompilerPolicy, CompilerPolicyDescriptor};
pub use report::{PatternCompilerDescriptor, PatternCompilerReport, PatternCompilerStatus};

/// Compiler report schema version.
pub const COMPILER_REPORT_SCHEMA_VERSION: &str = "1.0.0";
/// Stable adapter identity recorded in every report.
pub const COMPILER_ADAPTER_ID: &str = "pasol-pattern-compiler";
pub const COMPILER_ADAPTER_VERSION: &str = "1.0.0";
/// Policy identity.
pub const COMPILER_POLICY_ID: &str = "pasol-pattern-compiler";
pub const COMPILER_POLICY_VERSION: &str = "1.0.0";
/// Engine pin. Upgrades require an explicit planning decision.
pub const COMPILER_ENGINE: &str = "yara-x";
pub const COMPILER_ENGINE_VERSION: &str = "1.19.0";
/// Approved metadata and limits policy identifiers.
pub const COMPILER_METADATA_POLICY: &str = "pasol-pattern-metadata-1";
pub const COMPILER_LIMITS_PROFILE: &str = "phase-i-default";

/// Module allowlist, sorted. Any module outside this set is prohibited, and a
/// newly introduced engine module stays prohibited until a planning decision
/// approves it.
pub const ALLOWED_MODULES: [&str; 4] = ["hash", "math", "pe", "string"];

/// A successfully compiled pattern pack.
///
/// This type is a proof object. It has no `Serialize` or `Deserialize`
/// implementation, no public fields, and no public constructor, so it can only
/// originate from a compilation that passed every I2 trust check and every I3
/// policy check. Compiled rules stay in memory and are never written to disk.
#[derive(Debug, Clone)]
pub struct CompiledPatternPack {
    rules: std::sync::Arc<yara_x::Rules>,
    report: PatternCompilerReport,
}

impl CompiledPatternPack {
    /// Crate-internal constructor used only after a successful post-build audit.
    ///
    /// Unused in I3.1, which establishes contracts only. The post-build audit
    /// that calls it arrives in I3.4.
    #[allow(dead_code)]
    pub(crate) fn new(
        rules: std::sync::Arc<yara_x::Rules>,
        report: PatternCompilerReport,
    ) -> Result<Self, PatternCompilerError> {
        if !report.status.is_success() {
            return Err(PatternCompilerError::Internal(
                "compiled pack requires a compiled report".into(),
            ));
        }
        Ok(Self { rules, report })
    }

    /// Deterministic evidence for this compilation.
    pub fn report(&self) -> &PatternCompilerReport {
        &self.report
    }

    /// Read-only access to the compiled rules.
    ///
    /// Reserved for future worker integration. I3 must not use this to scan.
    pub fn rules(&self) -> &yara_x::Rules {
        &self.rules
    }
}

/// A failed compilation.
///
/// Carries deterministic evidence alongside the typed cause. No partial
/// [`CompiledPatternPack`] is ever produced on failure.
#[derive(Debug, Clone)]
pub struct PatternCompileFailure {
    pub report: PatternCompilerReport,
    pub error: PatternCompilerError,
}

impl PatternCompileFailure {
    pub fn new(report: PatternCompilerReport, error: PatternCompilerError) -> Self {
        Self { report, error }
    }
}

impl std::fmt::Display for PatternCompileFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for PatternCompileFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
