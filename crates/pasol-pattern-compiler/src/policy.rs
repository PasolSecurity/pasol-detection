//! Compiler policy identity, module allowlist, and bounded compiler limits.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::PatternCompilerError;
use crate::{
    ALLOWED_MODULES, COMPILER_ENGINE, COMPILER_ENGINE_VERSION, COMPILER_LIMITS_PROFILE,
    COMPILER_METADATA_POLICY, COMPILER_POLICY_ID, COMPILER_POLICY_VERSION,
};

/// Bounded compiler limits. Every field is validated against a hard ceiling
/// before compilation so that a configured policy can tighten, never widen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerLimits {
    pub max_sources: u32,
    pub max_source_bytes: u64,
    pub max_namespaces: u32,
    pub max_rules: u32,
    pub max_patterns_total: u32,
    pub max_patterns_per_rule: u32,
    pub max_tags_per_rule: u32,
    pub max_metadata_per_rule: u32,
    pub max_imports: u32,
    pub max_compiler_warnings: usize,
    pub max_diagnostics: u32,
    pub max_diagnostic_message_bytes: u32,
    pub max_report_bytes: u64,
}

impl Default for CompilerLimits {
    fn default() -> Self {
        Self {
            max_sources: 64,
            max_source_bytes: 4 * 1024 * 1024,
            max_namespaces: 32,
            max_rules: 2_000,
            max_patterns_total: 16_000,
            max_patterns_per_rule: 256,
            max_tags_per_rule: 32,
            max_metadata_per_rule: 32,
            max_imports: 4,
            max_compiler_warnings: 64,
            max_diagnostics: 128,
            max_diagnostic_message_bytes: 4 * 1024,
            max_report_bytes: 1024 * 1024,
        }
    }
}

impl CompilerLimits {
    /// Hard ceilings. A configured policy may not exceed these values.
    pub fn ceilings() -> Self {
        Self {
            max_sources: 256,
            max_source_bytes: 16 * 1024 * 1024,
            max_namespaces: 128,
            max_rules: 10_000,
            max_patterns_total: 64_000,
            max_patterns_per_rule: 1_024,
            max_tags_per_rule: 128,
            max_metadata_per_rule: 128,
            max_imports: 16,
            max_compiler_warnings: 256,
            max_diagnostics: 512,
            max_diagnostic_message_bytes: 16 * 1024,
            max_report_bytes: 4 * 1024 * 1024,
        }
    }

    /// Reject zero values and any value above its hard ceiling.
    pub fn validate(&self) -> Result<(), PatternCompilerError> {
        let hard = Self::ceilings();
        let values: [(u64, u64, &str); 13] = [
            (
                self.max_sources as u64,
                hard.max_sources as u64,
                "max_sources",
            ),
            (
                self.max_source_bytes,
                hard.max_source_bytes,
                "max_source_bytes",
            ),
            (
                self.max_namespaces as u64,
                hard.max_namespaces as u64,
                "max_namespaces",
            ),
            (self.max_rules as u64, hard.max_rules as u64, "max_rules"),
            (
                self.max_patterns_total as u64,
                hard.max_patterns_total as u64,
                "max_patterns_total",
            ),
            (
                self.max_patterns_per_rule as u64,
                hard.max_patterns_per_rule as u64,
                "max_patterns_per_rule",
            ),
            (
                self.max_tags_per_rule as u64,
                hard.max_tags_per_rule as u64,
                "max_tags_per_rule",
            ),
            (
                self.max_metadata_per_rule as u64,
                hard.max_metadata_per_rule as u64,
                "max_metadata_per_rule",
            ),
            (
                self.max_imports as u64,
                hard.max_imports as u64,
                "max_imports",
            ),
            (
                self.max_compiler_warnings as u64,
                hard.max_compiler_warnings as u64,
                "max_compiler_warnings",
            ),
            (
                self.max_diagnostics as u64,
                hard.max_diagnostics as u64,
                "max_diagnostics",
            ),
            (
                self.max_diagnostic_message_bytes as u64,
                hard.max_diagnostic_message_bytes as u64,
                "max_diagnostic_message_bytes",
            ),
            (
                self.max_report_bytes,
                hard.max_report_bytes,
                "max_report_bytes",
            ),
        ];
        if let Some((_, _, name)) = values
            .into_iter()
            .find(|(value, ceiling, _)| *value == 0 || *value > *ceiling)
        {
            return Err(PatternCompilerError::InvalidPolicy(format!(
                "invalid limit: {name}"
            )));
        }
        Ok(())
    }
}

/// Full compiler policy. `engine_version` is the exact pinned engine build the
/// adapter is allowed to drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerPolicy {
    pub policy_id: String,
    pub policy_version: String,
    pub engine: String,
    pub engine_version: String,
    pub metadata_policy: String,
    pub limits_profile: String,
    pub allowed_modules: Vec<String>,
    pub limits: CompilerLimits,
}

impl Default for CompilerPolicy {
    fn default() -> Self {
        Self {
            policy_id: COMPILER_POLICY_ID.into(),
            policy_version: COMPILER_POLICY_VERSION.into(),
            engine: COMPILER_ENGINE.into(),
            engine_version: COMPILER_ENGINE_VERSION.into(),
            metadata_policy: COMPILER_METADATA_POLICY.into(),
            limits_profile: COMPILER_LIMITS_PROFILE.into(),
            allowed_modules: ALLOWED_MODULES.iter().map(|m| (*m).to_string()).collect(),
            limits: CompilerLimits::default(),
        }
    }
}

impl CompilerPolicy {
    /// Validate policy identity, engine pin, module allowlist, and limits.
    ///
    /// The allowlist is compared as an exact sorted set. A policy naming any
    /// module outside the approved set fails closed, so a newly introduced
    /// engine module cannot be silently accepted.
    pub fn validate(&self) -> Result<(), PatternCompilerError> {
        if self.policy_id != COMPILER_POLICY_ID {
            return Err(PatternCompilerError::InvalidPolicy(
                "unexpected policy identifier".into(),
            ));
        }
        if self.policy_version != COMPILER_POLICY_VERSION {
            return Err(PatternCompilerError::InvalidPolicy(
                "unsupported policy version".into(),
            ));
        }
        if self.metadata_policy != COMPILER_METADATA_POLICY {
            return Err(PatternCompilerError::InvalidPolicy(
                "unsupported metadata policy".into(),
            ));
        }
        if self.limits_profile != COMPILER_LIMITS_PROFILE {
            return Err(PatternCompilerError::InvalidPolicy(
                "unsupported limits profile".into(),
            ));
        }
        if self.engine != COMPILER_ENGINE {
            return Err(PatternCompilerError::UnsupportedEngine(self.engine.clone()));
        }
        if self.engine_version != COMPILER_ENGINE_VERSION {
            return Err(PatternCompilerError::UnsupportedEngine(
                self.engine_version.clone(),
            ));
        }
        let mut configured = self.allowed_modules.clone();
        configured.sort();
        configured.dedup();
        if configured.len() != self.allowed_modules.len() {
            return Err(PatternCompilerError::InvalidPolicy(
                "duplicate module in allowlist".into(),
            ));
        }
        if configured != ALLOWED_MODULES {
            return Err(PatternCompilerError::InvalidPolicy(
                "module allowlist does not match the approved set".into(),
            ));
        }
        self.limits.validate()
    }

    /// Whether a module name is permitted under this policy.
    pub fn permits_module(&self, module: &str) -> bool {
        self.allowed_modules.iter().any(|m| m == module)
    }

    /// Engine version parsed as semver, for compatibility comparison.
    pub fn engine_semver(&self) -> Result<semver::Version, PatternCompilerError> {
        semver::Version::parse(&self.engine_version)
            .map_err(|_| PatternCompilerError::UnsupportedEngine(self.engine_version.clone()))
    }

    /// Serializable descriptor embedded in the versioned report.
    pub fn descriptor(&self) -> CompilerPolicyDescriptor {
        let mut modules = self.allowed_modules.clone();
        modules.sort();
        CompilerPolicyDescriptor {
            policy_id: self.policy_id.clone(),
            policy_version: self.policy_version.clone(),
            metadata_policy: self.metadata_policy.clone(),
            limits_profile: self.limits_profile.clone(),
            allowed_modules: modules,
        }
    }
}

/// Deterministic policy facts recorded in the compiler report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CompilerPolicyDescriptor {
    pub policy_id: String,
    pub policy_version: String,
    pub metadata_policy: String,
    pub limits_profile: String,
    pub allowed_modules: Vec<String>,
}
