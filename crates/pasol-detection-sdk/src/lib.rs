#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const FEATURE_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureState {
    Present,
    Absent,
    Unknown,
    Truncated,
    NotApplicable,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct FeatureEvidence {
    pub path: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct Feature {
    pub id: String,
    pub state: FeatureState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FeatureEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct FeatureSource {
    pub parser: String,
    pub parser_version: String,
    pub parser_schema_version: String,
    pub sha256: String,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeatureReportStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct FeatureReport {
    pub schema_version: String,
    pub extractor: String,
    pub extractor_version: String,
    pub source: FeatureSource,
    pub status: FeatureReportStatus,
    pub features: Vec<Feature>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParserReport {
    pub schema_version: String,
    pub parser: String,
    pub parser_version: String,
    pub file_type: String,
    pub sha256: String,
    pub size: u64,
    pub status: String,
    pub metadata: Value,
    #[serde(default)]
    pub warnings: Vec<ParserWarning>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ParserWarning {
    pub code: String,
    pub message: String,
    pub offset: Option<String>,
}

#[derive(Debug, Error)]
pub enum FeatureError {
    #[error("unsupported parser schema version: {0}")]
    UnsupportedSchema(String),
    #[error("invalid parser report: {0}")]
    InvalidReport(String),
    #[error("unsupported parser: {0}")]
    UnsupportedParser(String),
}

pub trait FeatureExtractor: Send + Sync {
    fn descriptor(&self) -> &'static str;
    fn supports(&self, parser_name: &str, schema_version: &str, file_type: &str) -> bool;
    fn extract(&self, report: &ParserReport) -> Result<FeatureReport, FeatureError>;
}

pub fn sort_report(report: &mut FeatureReport) {
    report
        .features
        .sort_by(|left, right| left.id.cmp(&right.id));
    for feature in &mut report.features {
        feature
            .evidence
            .sort_by(|left, right| left.path.cmp(&right.path));
    }
}

pub fn feature(id: impl Into<String>, state: FeatureState, value: Option<Value>) -> Feature {
    Feature {
        id: id.into(),
        state,
        value,
        evidence: Vec::new(),
    }
}

pub fn evidence(path: impl Into<String>, summary: impl Into<String>) -> FeatureEvidence {
    FeatureEvidence {
        path: path.into(),
        summary: summary.into(),
        attributes: BTreeMap::new(),
    }
}
