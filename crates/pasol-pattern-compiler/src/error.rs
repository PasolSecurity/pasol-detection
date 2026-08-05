//! Typed compiler errors.
//!
//! Errors must remain free of machine-specific paths, source contents, and Rust
//! debug formatting so that structured output stays deterministic and private.

use thiserror::Error;

/// Failure classification for a pattern-pack compilation attempt.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PatternCompilerError {
    #[error("invalid compiler policy: {0}")]
    InvalidPolicy(String),
    #[error("unsupported engine: {0}")]
    UnsupportedEngine(String),
    #[error("input is not a proof-carrying pattern pack")]
    UnverifiedInput,
    #[error("include statements are forbidden")]
    IncludeForbidden,
    #[error("module is not permitted: {0}")]
    ModuleForbidden(String),
    #[error("compiler rejected the pattern pack")]
    CompilerRejected,
    #[error("compiler warnings are not permitted")]
    WarningRejected,
    #[error("metadata policy violation: {0}")]
    MetadataPolicy(String),
    #[error("global rules are forbidden: {0}")]
    GlobalRuleForbidden(String),
    #[error("duplicate rule: {0}")]
    DuplicateRule(String),
    #[error("duplicate metadata identifier: {0}")]
    DuplicateMetadataId(String),
    #[error("resource limit exceeded: {0}")]
    ResourceLimit(String),
    #[error("report validation failed: {0}")]
    ReportValidation(String),
    #[error("internal compiler failure: {0}")]
    Internal(String),
}

impl PatternCompilerError {
    /// Stable machine-readable code, suitable for evidence and future exit-code
    /// mapping without exposing message text.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPolicy(_) => "invalid_policy",
            Self::UnsupportedEngine(_) => "unsupported_engine",
            Self::UnverifiedInput => "unverified_input",
            Self::IncludeForbidden => "include_forbidden",
            Self::ModuleForbidden(_) => "module_forbidden",
            Self::CompilerRejected => "compiler_rejected",
            Self::WarningRejected => "warning_rejected",
            Self::MetadataPolicy(_) => "metadata_policy",
            Self::GlobalRuleForbidden(_) => "global_rule_forbidden",
            Self::DuplicateRule(_) => "duplicate_rule",
            Self::DuplicateMetadataId(_) => "duplicate_metadata_id",
            Self::ResourceLimit(_) => "resource_limit",
            Self::ReportValidation(_) => "report_validation",
            Self::Internal(_) => "internal",
        }
    }

    /// Whether the failure is a policy or integrity rejection rather than a
    /// malformed-input or internal condition.
    pub fn is_policy_rejection(&self) -> bool {
        matches!(
            self,
            Self::IncludeForbidden
                | Self::ModuleForbidden(_)
                | Self::WarningRejected
                | Self::MetadataPolicy(_)
                | Self::GlobalRuleForbidden(_)
                | Self::DuplicateRule(_)
                | Self::DuplicateMetadataId(_)
        )
    }
}
