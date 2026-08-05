#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PATTERN_SCHEMA_VERSION: &str = "1.0.0";
pub const PATTERN_ENGINE: &str = "yara-x";
pub const MAX_STRING_LENGTH: usize = 4096;
pub const MAX_METADATA_KEYS: usize = 64;
pub const MAX_SOURCE_FILES: usize = 256;
pub const MAX_SOURCE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PatternContractError {
    #[error("unsupported schema version: {0}")]
    UnsupportedSchema(String),
    #[error("invalid pattern contract: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternScanStatus {
    Completed,
    Timeout,
    ResourceLimited,
    WorkerFailed,
    InvalidInput,
    InvalidPack,
    UnsupportedEngine,
    NotEvaluated,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct PatternInput {
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternEngineDescriptor {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternPackIdentity {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub signature_state: PatternSignatureState,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatternSignatureState {
    Verified,
    Development,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternPackReference {
    pub identity: PatternPackIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct VerifiedPatternPack {
    reference: PatternPackReference,
}

impl VerifiedPatternPack {
    pub fn development(reference: PatternPackReference) -> Self {
        Self { reference }
    }
    pub fn identity(&self) -> &PatternPackIdentity {
        &self.reference.identity
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternLocation {
    pub offset: u64,
    pub length: u64,
    pub identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xor_key: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PatternRuleMatch {
    pub namespace: String,
    pub rule: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, PatternMetadataValue>,
    #[serde(default)]
    pub locations: Vec<PatternLocation>,
    #[serde(default)]
    pub evidence_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[serde(untagged)]
pub enum PatternMetadataValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PatternLimits {
    pub input_bytes: u64,
    pub pack_source_bytes: u64,
    pub source_files: u32,
    pub rules: u32,
    pub namespaces: u32,
    pub compile_time_ms: u32,
    pub scan_time_ms: u32,
    pub worker_wall_time_ms: u32,
    pub worker_memory_bytes: u64,
    pub matches_per_pattern: u32,
    pub matching_rules: u32,
    pub evidence_entries: u32,
    pub report_bytes: u64,
    pub compiler_warnings: u32,
}

impl Default for PatternLimits {
    fn default() -> Self {
        Self {
            input_bytes: 32 * 1024 * 1024,
            pack_source_bytes: 4 * 1024 * 1024,
            source_files: 64,
            rules: 2_000,
            namespaces: 32,
            compile_time_ms: 3_000,
            scan_time_ms: 2_000,
            worker_wall_time_ms: 6_000,
            worker_memory_bytes: 384 * 1024 * 1024,
            matches_per_pattern: 32,
            matching_rules: 128,
            evidence_entries: 1_024,
            report_bytes: 1_048_576,
            compiler_warnings: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AppliedPatternLimits {
    pub input_bytes: u64,
    pub report_bytes: u64,
    pub matching_rules: u32,
    pub evidence_entries: u32,
    pub matches_per_pattern: u32,
    pub compiler_warnings: u32,
    pub locations_per_rule: u32,
}

impl From<&PatternLimits> for AppliedPatternLimits {
    fn from(value: &PatternLimits) -> Self {
        Self {
            input_bytes: value.input_bytes,
            report_bytes: value.report_bytes,
            matching_rules: value.matching_rules,
            evidence_entries: value.evidence_entries,
            matches_per_pattern: value.matches_per_pattern,
            compiler_warnings: value.compiler_warnings,
            locations_per_rule: value.matches_per_pattern,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct PatternTiming {
    pub compile_time_ms: u32,
    pub scan_time_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PatternReport {
    pub schema_version: String,
    pub engine: PatternEngineDescriptor,
    pub pattern_pack: PatternPackIdentity,
    pub input: PatternInput,
    pub status: PatternScanStatus,
    #[serde(default)]
    pub matches: Vec<PatternRuleMatch>,
    #[serde(default)]
    pub warnings: Vec<PatternWarning>,
    pub limits: AppliedPatternLimits,
    pub timing: PatternTiming,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PatternScanRequest {
    pub schema_version: String,
    pub input: PatternInput,
    pub pack: VerifiedPatternPack,
    pub limits: PatternLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PatternWorkerRequest {
    pub schema_version: String,
    pub request: PatternScanRequest,
    pub input_size: u64,
    pub input_sha256: String,
    pub payload_length: u64,
    pub rule_sources: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PatternWorkerResponse {
    pub schema_version: String,
    pub report: PatternReport,
}

impl PatternInput {
    pub fn validate(&self, limits: &PatternLimits) -> Result<(), PatternContractError> {
        if !is_sha256(&self.sha256) {
            return Err(PatternContractError::Invalid(
                "input sha256 must be lowercase hex".into(),
            ));
        }
        if self.size_bytes > limits.input_bytes {
            return Err(PatternContractError::Invalid(
                "input exceeds configured limit".into(),
            ));
        }
        validate_string(self.file_type.as_deref(), "file_type")
    }
}

impl PatternScanRequest {
    pub fn validate(&self) -> Result<(), PatternContractError> {
        if self.schema_version != PATTERN_SCHEMA_VERSION {
            return Err(PatternContractError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        self.limits.validate()?;
        self.input.validate(&self.limits)?;
        validate_pack_identity(self.pack.identity())
    }
    pub fn to_validated_json(&self) -> Result<Value, PatternContractError> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        validate_schema("pattern-scan-request-1.0.0.schema.json", &value)?;
        Ok(value)
    }
    pub fn from_validated_json(value: &Value) -> Result<Self, PatternContractError> {
        let out: Self = serde_json::from_value(value.clone())
            .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        out.validate()?;
        validate_schema("pattern-scan-request-1.0.0.schema.json", value)?;
        Ok(out)
    }
}

impl PatternWorkerRequest {
    pub fn validate(&self) -> Result<(), PatternContractError> {
        if self.schema_version != PATTERN_SCHEMA_VERSION {
            return Err(PatternContractError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        self.request.validate()?;
        if self.input_size != self.request.input.size_bytes
            || self.payload_length != self.input_size
        {
            return Err(PatternContractError::Invalid(
                "input size and payload length mismatch".into(),
            ));
        }
        if self.input_sha256 != self.request.input.sha256 {
            return Err(PatternContractError::Invalid("input hash mismatch".into()));
        }
        if self.rule_sources.len() > self.request.limits.source_files as usize {
            return Err(PatternContractError::Invalid(
                "too many rule sources".into(),
            ));
        }
        let mut total = 0usize;
        let mut normalized = std::collections::BTreeSet::new();
        for (path, source) in &self.rule_sources {
            if normalize_canonical_path(path).is_err() || !normalized.insert(path) {
                return Err(PatternContractError::Invalid(
                    "invalid or colliding rule source path".into(),
                ));
            }
            if source.chars().any(|c| c.is_control()) {
                return Err(PatternContractError::Invalid(
                    "control character in rule source".into(),
                ));
            }
            if source.len() > self.request.limits.pack_source_bytes as usize {
                return Err(PatternContractError::Invalid(
                    "rule source too large".into(),
                ));
            }
            total = total
                .checked_add(source.len())
                .ok_or_else(|| PatternContractError::Invalid("rule source size overflow".into()))?;
        }
        if total > self.request.limits.pack_source_bytes as usize {
            return Err(PatternContractError::Invalid(
                "aggregate rule source too large".into(),
            ));
        }
        if self.payload_length > self.request.limits.input_bytes {
            return Err(PatternContractError::Invalid(
                "payload exceeds input limit".into(),
            ));
        }
        Ok(())
    }
    pub fn bind_payload(&self, payload: &[u8]) -> Result<(), PatternContractError> {
        if payload.len() as u64 != self.payload_length {
            return Err(PatternContractError::Invalid(
                "payload length mismatch".into(),
            ));
        }
        let hash = hex::encode(Sha256::digest(payload));
        if hash != self.input_sha256 {
            return Err(PatternContractError::Invalid(
                "payload sha256 mismatch".into(),
            ));
        }
        Ok(())
    }
    pub fn to_validated_json(&self) -> Result<Value, PatternContractError> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        validate_schema("pattern-worker-request-1.0.0.schema.json", &value)?;
        Ok(value)
    }
    pub fn from_validated_json(value: &Value) -> Result<Self, PatternContractError> {
        let out: Self = serde_json::from_value(value.clone())
            .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        out.validate()?;
        validate_schema("pattern-worker-request-1.0.0.schema.json", value)?;
        Ok(out)
    }
}

impl PatternWorkerResponse {
    pub fn validate(&self) -> Result<(), PatternContractError> {
        if self.schema_version != PATTERN_SCHEMA_VERSION {
            return Err(PatternContractError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        if self.report.schema_version != self.schema_version {
            return Err(PatternContractError::Invalid(
                "nested report schema mismatch".into(),
            ));
        }
        self.report.validate()
    }
    pub fn to_validated_json(&self) -> Result<Value, PatternContractError> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        validate_schema("pattern-worker-response-1.0.0.schema.json", &value)?;
        Ok(value)
    }
    pub fn from_validated_json(value: &Value) -> Result<Self, PatternContractError> {
        let out: Self = serde_json::from_value(value.clone())
            .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        out.validate()?;
        validate_schema("pattern-worker-response-1.0.0.schema.json", value)?;
        Ok(out)
    }
}

impl PatternLimits {
    pub fn validate(&self) -> Result<(), PatternContractError> {
        let hard = Self {
            input_bytes: 128 * 1024 * 1024,
            pack_source_bytes: 16 * 1024 * 1024,
            source_files: 256,
            rules: 10_000,
            namespaces: 128,
            compile_time_ms: 10_000,
            scan_time_ms: 10_000,
            worker_wall_time_ms: 20_000,
            worker_memory_bytes: 768 * 1024 * 1024,
            matches_per_pattern: 256,
            matching_rules: 1_024,
            evidence_entries: 8_192,
            report_bytes: 4 * 1024 * 1024,
            compiler_warnings: 256,
        };
        let values = [
            (self.input_bytes, hard.input_bytes, "input_bytes"),
            (
                self.pack_source_bytes,
                hard.pack_source_bytes,
                "pack_source_bytes",
            ),
            (
                self.source_files as u64,
                hard.source_files as u64,
                "source_files",
            ),
            (self.rules as u64, hard.rules as u64, "rules"),
            (self.namespaces as u64, hard.namespaces as u64, "namespaces"),
            (
                self.compile_time_ms as u64,
                hard.compile_time_ms as u64,
                "compile_time_ms",
            ),
            (
                self.scan_time_ms as u64,
                hard.scan_time_ms as u64,
                "scan_time_ms",
            ),
            (
                self.worker_wall_time_ms as u64,
                hard.worker_wall_time_ms as u64,
                "worker_wall_time_ms",
            ),
            (
                self.worker_memory_bytes,
                hard.worker_memory_bytes,
                "worker_memory_bytes",
            ),
            (
                self.matches_per_pattern as u64,
                hard.matches_per_pattern as u64,
                "matches_per_pattern",
            ),
            (
                self.matching_rules as u64,
                hard.matching_rules as u64,
                "matching_rules",
            ),
            (
                self.evidence_entries as u64,
                hard.evidence_entries as u64,
                "evidence_entries",
            ),
            (self.report_bytes, hard.report_bytes, "report_bytes"),
            (
                self.compiler_warnings as u64,
                hard.compiler_warnings as u64,
                "compiler_warnings",
            ),
        ];
        if let Some((_, _, name)) = values
            .into_iter()
            .find(|(value, ceiling, _)| *value == 0 || *value > *ceiling)
        {
            return Err(PatternContractError::Invalid(format!(
                "invalid limit: {name}"
            )));
        }
        Ok(())
    }
}

impl PatternReport {
    pub fn normalize(&mut self) {
        self.matches
            .sort_by(|a, b| a.namespace.cmp(&b.namespace).then(a.rule.cmp(&b.rule)));
        for item in &mut self.matches {
            item.tags.sort();
            item.locations.sort_by(|a, b| {
                a.offset
                    .cmp(&b.offset)
                    .then(a.identifier.cmp(&b.identifier))
                    .then(a.length.cmp(&b.length))
            });
        }
        self.warnings
            .sort_by(|a, b| a.code.cmp(&b.code).then(a.message.cmp(&b.message)));
    }

    pub fn validate(&self) -> Result<(), PatternContractError> {
        if self.schema_version != PATTERN_SCHEMA_VERSION {
            return Err(PatternContractError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        if self.engine.id != PATTERN_ENGINE {
            return Err(PatternContractError::Invalid("unsupported engine".into()));
        }
        if !is_sha256(&self.input.sha256) || !is_sha256(&self.pattern_pack.sha256) {
            return Err(PatternContractError::Invalid("invalid sha256".into()));
        }
        validate_string(Some(&self.engine.id), "engine")?;
        validate_string(Some(&self.engine.version), "engine_version")?;
        validate_string(Some(&self.pattern_pack.id), "pack_id")?;
        validate_string(Some(&self.pattern_pack.version), "pack_version")?;
        if !matches!(self.status, PatternScanStatus::Completed) && !self.matches.is_empty() {
            return Err(PatternContractError::Invalid(
                "non-completed report cannot contain matches".into(),
            ));
        }
        if self.matches.len() as u32 > self.limits.matching_rules
            || self.warnings.len() as u32 > self.limits.compiler_warnings
        {
            return Err(PatternContractError::Invalid(
                "applied output limit exceeded".into(),
            ));
        }
        let locations: usize = self.matches.iter().map(|m| m.locations.len()).sum();
        if locations as u32 > self.limits.evidence_entries {
            return Err(PatternContractError::Invalid(
                "evidence limit exceeded".into(),
            ));
        }
        if self.matches.len() > 1_024 || self.warnings.len() > 256 {
            return Err(PatternContractError::Invalid(
                "report collection limit exceeded".into(),
            ));
        }
        for item in &self.matches {
            validate_string(Some(&item.namespace), "namespace")?;
            validate_string(Some(&item.rule), "rule")?;
            if item.tags.len() > 64
                || item.metadata.len() > MAX_METADATA_KEYS
                || item.locations.len() as u32 > self.limits.locations_per_rule
            {
                return Err(PatternContractError::Invalid(
                    "match evidence limit exceeded".into(),
                ));
            }
            for tag in &item.tags {
                validate_string(Some(tag), "tag")?;
            }
            for (key, value) in &item.metadata {
                validate_string(Some(key), "metadata key")?;
                if let PatternMetadataValue::String(value) = value {
                    validate_string(Some(value), "metadata value")?;
                }
            }
            for location in &item.locations {
                validate_string(Some(&location.identifier), "pattern identifier")?;
            }
        }
        for warning in &self.warnings {
            validate_string(Some(&warning.code), "warning code")?;
            validate_string(Some(&warning.message), "warning message")?;
        }
        let bytes =
            serde_json::to_vec(self).map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        if bytes.len() as u64 > self.limits.report_bytes {
            return Err(PatternContractError::Invalid(
                "report size limit exceeded".into(),
            ));
        }
        Ok(())
    }

    pub fn to_validated_json(&self) -> Result<Value, PatternContractError> {
        self.validate()?;
        let value =
            serde_json::to_value(self).map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        validate_schema("pattern-report-1.0.0.schema.json", &value)?;
        Ok(value)
    }
    pub fn from_validated_json(value: &Value) -> Result<Self, PatternContractError> {
        let out: Self = serde_json::from_value(value.clone())
            .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
        out.validate()?;
        validate_schema("pattern-report-1.0.0.schema.json", value)?;
        Ok(out)
    }
}

fn validate_pack_identity(identity: &PatternPackIdentity) -> Result<(), PatternContractError> {
    if !is_sha256(&identity.sha256) {
        return Err(PatternContractError::Invalid("invalid pack sha256".into()));
    }
    validate_string(Some(&identity.id), "pack id")?;
    validate_string(Some(&identity.version), "pack version")?;
    Ok(())
}

fn normalize_canonical_path(path: &str) -> Result<(), PatternContractError> {
    if path.is_empty()
        || path.contains('\\')
        || path.starts_with('/')
        || path.contains(':')
        || path
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.chars().any(|c| c.is_control()))
    {
        return Err(PatternContractError::Invalid(
            "path is not canonical".into(),
        ));
    }
    Ok(())
}

pub fn normalize_relative_path(path: &str) -> Result<String, PatternContractError> {
    if path.is_empty()
        || path.contains('\\')
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains(':')
    {
        return Err(PatternContractError::Invalid(
            "path must be a normalized relative path".into(),
        ));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(PatternContractError::Invalid(
                "path traversal is forbidden".into(),
            ));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(PatternContractError::Invalid("empty path".into()));
    }
    Ok(parts.join("/"))
}

fn validate_schema(name: &str, value: &Value) -> Result<(), PatternContractError> {
    let schema: Value = match name {
        "pattern-report-1.0.0.schema.json" => serde_json::from_str(include_str!(
            "../../../schemas/pattern-report-1.0.0.schema.json"
        )),
        "pattern-scan-request-1.0.0.schema.json" => serde_json::from_str(include_str!(
            "../../../schemas/pattern-scan-request-1.0.0.schema.json"
        )),
        _ => return Err(PatternContractError::Invalid("unknown schema".into())),
    }
    .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    validator
        .validate(value)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))
}

fn validate_string(value: Option<&str>, name: &str) -> Result<(), PatternContractError> {
    if value.is_some_and(|v| v.is_empty() || v.len() > MAX_STRING_LENGTH) {
        return Err(PatternContractError::Invalid(format!("invalid {name}")));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(status: PatternScanStatus) -> PatternReport {
        PatternReport {
            schema_version: PATTERN_SCHEMA_VERSION.into(),
            engine: PatternEngineDescriptor {
                id: PATTERN_ENGINE.into(),
                version: "1.19.0".into(),
            },
            pattern_pack: PatternPackIdentity {
                id: "pasol.test".into(),
                version: "0.1.0".into(),
                sha256: "a".repeat(64),
                signature_state: PatternSignatureState::Development,
            },
            input: PatternInput {
                sha256: "b".repeat(64),
                size_bytes: 0,
                file_type: None,
            },
            status,
            matches: Vec::new(),
            warnings: Vec::new(),
            limits: AppliedPatternLimits::from(&PatternLimits::default()),
            timing: PatternTiming::default(),
        }
    }

    #[test]
    fn statuses_and_no_match_are_distinct() {
        assert_ne!(
            report(PatternScanStatus::Completed).status,
            PatternScanStatus::NotEvaluated
        );
        assert!(
            report(PatternScanStatus::Completed)
                .to_validated_json()
                .is_ok()
        );
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let mut value = report(PatternScanStatus::Completed);
        value.schema_version = "2.0.0".into();
        assert!(matches!(
            value.validate(),
            Err(PatternContractError::UnsupportedSchema(_))
        ));
    }

    #[test]
    fn ordering_is_deterministic_and_paths_are_bounded() {
        let mut value = report(PatternScanStatus::Completed);
        value.matches.push(PatternRuleMatch {
            namespace: "z".into(),
            rule: "b".into(),
            tags: vec!["z".into(), "a".into()],
            metadata: BTreeMap::new(),
            locations: vec![],
            evidence_truncated: false,
        });
        value.matches.push(PatternRuleMatch {
            namespace: "a".into(),
            rule: "a".into(),
            tags: vec![],
            metadata: BTreeMap::new(),
            locations: vec![],
            evidence_truncated: false,
        });
        value.normalize();
        assert_eq!(value.matches[0].namespace, "a");
        assert_eq!(value.matches[1].tags, vec!["a", "z"]);
        assert!(normalize_relative_path("rules/test.yar").is_ok());
        assert!(normalize_relative_path("../test.yar").is_err());
        assert!(normalize_relative_path("C:/test.yar").is_err());
    }
}
