//! Versioned, deterministic compiler report.

use pasol_patterns::{PatternEngineDescriptor, PatternPackIdentity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::diagnostics::{
    PatternCompilerDiagnostic, PatternDiagnosticSeverity, sort_diagnostics, truncate_diagnostics,
};
use crate::error::PatternCompilerError;
use crate::policy::{CompilerLimits, CompilerPolicyDescriptor};
use crate::{COMPILER_ADAPTER_ID, COMPILER_ENGINE, COMPILER_REPORT_SCHEMA_VERSION};

/// Identity of the adapter that produced a report.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternCompilerDescriptor {
    pub id: String,
    pub version: String,
}

impl Default for PatternCompilerDescriptor {
    fn default() -> Self {
        Self {
            id: COMPILER_ADAPTER_ID.into(),
            version: crate::COMPILER_ADAPTER_VERSION.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternCompilerStatus {
    Compiled,
    Rejected,
    ResourceLimited,
    UnsupportedEngine,
    InternalFailure,
}

impl PatternCompilerStatus {
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Compiled)
    }
}

/// Deterministic compilation evidence.
///
/// The report deliberately excludes elapsed time, memory use, process
/// identifiers, host paths, and timestamps so that identical inputs produce
/// byte-identical output on repeated runs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternCompilerReport {
    pub schema_version: String,
    pub adapter: PatternCompilerDescriptor,
    pub engine: PatternEngineDescriptor,
    pub policy: CompilerPolicyDescriptor,
    pub pattern_pack: PatternPackIdentity,
    pub status: PatternCompilerStatus,
    pub source_count: u32,
    pub namespace_count: u32,
    pub rule_count: u32,
    pub public_rule_count: u32,
    pub private_rule_count: u32,
    pub global_rule_count: u32,
    pub pattern_count: u32,
    #[serde(default)]
    pub imported_modules: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<PatternCompilerDiagnostic>,
    #[serde(default)]
    pub errors: Vec<PatternCompilerDiagnostic>,
    #[serde(default)]
    pub diagnostics_truncated: bool,
}

impl PatternCompilerReport {
    /// Apply the documented deterministic ordering and bounded truncation.
    ///
    /// Normalization is idempotent: running it twice yields the same value.
    pub fn normalize(&mut self, limits: &CompilerLimits) {
        self.imported_modules.sort();
        self.imported_modules.dedup();
        sort_diagnostics(&mut self.warnings);
        sort_diagnostics(&mut self.errors);
        let max = limits.max_diagnostics as usize;
        let warnings_truncated = truncate_diagnostics(&mut self.warnings, max);
        let errors_truncated = truncate_diagnostics(&mut self.errors, max);
        self.diagnostics_truncated =
            self.diagnostics_truncated || warnings_truncated || errors_truncated;
    }

    /// Validate schema version, engine, status/content agreement, bounds, and
    /// serialized size.
    pub fn validate(&self, limits: &CompilerLimits) -> Result<(), PatternCompilerError> {
        if self.schema_version != COMPILER_REPORT_SCHEMA_VERSION {
            return Err(PatternCompilerError::ReportValidation(format!(
                "unsupported schema version: {}",
                self.schema_version
            )));
        }
        if self.engine.id != COMPILER_ENGINE {
            return Err(PatternCompilerError::UnsupportedEngine(
                self.engine.id.clone(),
            ));
        }
        if self.adapter.id != COMPILER_ADAPTER_ID {
            return Err(PatternCompilerError::ReportValidation(
                "unexpected adapter identifier".into(),
            ));
        }

        // A successful report carries no errors and, under the initial
        // zero-warning policy, no warnings either.
        if self.status.is_success() {
            if !self.errors.is_empty() {
                return Err(PatternCompilerError::ReportValidation(
                    "compiled report cannot contain errors".into(),
                ));
            }
            if !self.warnings.is_empty() {
                return Err(PatternCompilerError::ReportValidation(
                    "compiled report cannot contain warnings under the zero-warning policy".into(),
                ));
            }
            if self.global_rule_count != 0 {
                return Err(PatternCompilerError::GlobalRuleForbidden(
                    "compiled report reports global rules".into(),
                ));
            }
        } else if self.rule_count != 0 || self.pattern_count != 0 {
            return Err(PatternCompilerError::ReportValidation(
                "rejected report cannot claim compiled rules".into(),
            ));
        }

        let public_private = self
            .public_rule_count
            .checked_add(self.private_rule_count)
            .ok_or(PatternCompilerError::ReportValidation(
                "rule count overflow".into(),
            ))?;
        if public_private != self.rule_count {
            return Err(PatternCompilerError::ReportValidation(
                "public and private rule counts do not sum to the rule count".into(),
            ));
        }

        let counts: [(u64, u64, &str); 5] = [
            (
                self.source_count as u64,
                limits.max_sources as u64,
                "source_count",
            ),
            (
                self.namespace_count as u64,
                limits.max_namespaces as u64,
                "namespace_count",
            ),
            (
                self.rule_count as u64,
                limits.max_rules as u64,
                "rule_count",
            ),
            (
                self.pattern_count as u64,
                limits.max_patterns_total as u64,
                "pattern_count",
            ),
            (
                self.imported_modules.len() as u64,
                limits.max_imports as u64,
                "imported_modules",
            ),
        ];
        if let Some((_, _, name)) = counts.into_iter().find(|(value, max, _)| value > max) {
            return Err(PatternCompilerError::ResourceLimit(name.into()));
        }

        if self.warnings.len() as u64 > limits.max_diagnostics as u64
            || self.errors.len() as u64 > limits.max_diagnostics as u64
        {
            return Err(PatternCompilerError::ResourceLimit("diagnostics".into()));
        }

        let max_message = limits.max_diagnostic_message_bytes as usize;
        for diagnostic in self.warnings.iter().chain(self.errors.iter()) {
            diagnostic.validate(max_message)?;
        }
        if self
            .warnings
            .iter()
            .any(|d| d.severity != PatternDiagnosticSeverity::Warning)
            || self
                .errors
                .iter()
                .any(|d| d.severity != PatternDiagnosticSeverity::Error)
        {
            return Err(PatternCompilerError::ReportValidation(
                "diagnostic severity does not match its collection".into(),
            ));
        }

        for module in &self.imported_modules {
            if !crate::ALLOWED_MODULES.contains(&module.as_str()) {
                return Err(PatternCompilerError::ModuleForbidden(module.clone()));
            }
        }

        let bytes = serde_json::to_vec(self)
            .map_err(|e| PatternCompilerError::ReportValidation(e.to_string()))?;
        if bytes.len() as u64 > limits.max_report_bytes {
            return Err(PatternCompilerError::ResourceLimit("report_bytes".into()));
        }
        Ok(())
    }

    /// Validate semantically, then against the checked-in JSON schema.
    pub fn to_validated_json(
        &self,
        limits: &CompilerLimits,
    ) -> Result<Value, PatternCompilerError> {
        self.validate(limits)?;
        let value = serde_json::to_value(self)
            .map_err(|e| PatternCompilerError::ReportValidation(e.to_string()))?;
        validate_schema(&value)?;
        Ok(value)
    }

    /// Parse untrusted JSON through both schema and semantic validation.
    pub fn from_validated_json(
        value: &Value,
        limits: &CompilerLimits,
    ) -> Result<Self, PatternCompilerError> {
        let out: Self = serde_json::from_value(value.clone())
            .map_err(|e| PatternCompilerError::ReportValidation(e.to_string()))?;
        out.validate(limits)?;
        validate_schema(value)?;
        Ok(out)
    }
}

fn validate_schema(value: &Value) -> Result<(), PatternCompilerError> {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/pattern-compiler-report-1.0.0.schema.json"
    ))
    .map_err(|e| PatternCompilerError::ReportValidation(e.to_string()))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| PatternCompilerError::ReportValidation(e.to_string()))?;
    validator
        .validate(value)
        .map_err(|e| PatternCompilerError::ReportValidation(e.to_string()))
}
