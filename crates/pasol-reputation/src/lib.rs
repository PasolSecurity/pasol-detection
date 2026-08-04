#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};
use thiserror::Error;

pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";
pub const STORE_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReputationState {
    KnownBenign,
    KnownMalicious,
    Suspicious,
    Unknown,
    Unavailable,
    RateLimited,
    Unauthorized,
    ProviderError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderDescriptor {
    pub id: String,
    pub name: String,
    pub version: String,
    pub offline: bool,
    pub authentication_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheMetadata {
    pub hit: bool,
    pub stored_at: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationResult {
    pub provider: String,
    pub provider_version: String,
    pub state: ReputationState,
    pub confidence: Option<String>,
    pub labels: Vec<String>,
    pub reason: Option<String>,
    pub source: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub cache: CacheMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationReport {
    pub schema_version: String,
    pub sha256: String,
    pub queried_at: String,
    pub status: String,
    pub results: Vec<ReputationResult>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationEntry {
    pub sha256: String,
    pub state: ReputationState,
    pub reason: Option<String>,
    pub source: Option<String>,
    pub labels: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalStore {
    pub schema_version: String,
    pub entries: Vec<ReputationEntry>,
}

#[derive(Debug, Error)]
pub enum ReputationError {
    #[error("invalid SHA-256 hash")]
    InvalidHash,
    #[error("schema validation failed: {0}")]
    Schema(String),
    #[error("store I/O error: {0}")]
    Io(String),
    #[error("invalid store: {0}")]
    InvalidStore(String),
}

pub fn validate_report_json(value: &Value) -> Result<(), String> {
    validate(
        value,
        include_str!("../../../schemas/reputation-report-1.0.0.schema.json"),
    )
}
pub fn validate_store_json(value: &Value) -> Result<(), String> {
    validate(
        value,
        include_str!("../../../schemas/local-reputation-store-1.0.0.schema.json"),
    )
}
fn validate(value: &Value, schema_text: &str) -> Result<(), String> {
    let schema: Value = serde_json::from_str(schema_text).map_err(|e| e.to_string())?;
    let validator = jsonschema::validator_for(&schema).map_err(|e| e.to_string())?;
    validator.validate(value).map_err(|e| e.to_string())
}

pub fn validate_sha256(hash: &str) -> Result<(), ReputationError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(ReputationError::InvalidHash);
    }
    Ok(())
}
pub fn now_utc() -> String {
    "1970-01-01T00:00:00Z".to_owned()
}

impl LocalStore {
    pub fn empty() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }
    pub fn load(path: &Path) -> Result<Self, ReputationError> {
        let bytes = fs::read(path).map_err(|e| ReputationError::Io(e.to_string()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        validate_store_json(&value).map_err(ReputationError::Schema)?;
        serde_json::from_value(value).map_err(|e| ReputationError::InvalidStore(e.to_string()))
    }
    pub fn save_atomic(&self, path: &Path) -> Result<(), ReputationError> {
        let value =
            serde_json::to_value(self).map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        validate_store_json(&value).map_err(ReputationError::Schema)?;
        let tmp = path.with_extension("tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(&value)
                .map_err(|e| ReputationError::InvalidStore(e.to_string()))?,
        )
        .map_err(|e| ReputationError::Io(e.to_string()))?;
        fs::rename(&tmp, path).map_err(|e| ReputationError::Io(e.to_string()))
    }
    pub fn lookup(&self, hash: &str) -> Result<ReputationResult, ReputationError> {
        validate_sha256(hash)?;
        let mut matches: Vec<&ReputationEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.enabled
                    && e.sha256 == hash
                    && e.expires_at
                        .as_deref()
                        .is_none_or(|expiry| expiry > now_utc().as_str())
            })
            .collect();
        matches.sort_by_key(|e| match e.state {
            ReputationState::KnownMalicious => 0,
            ReputationState::Suspicious => 1,
            ReputationState::KnownBenign => 2,
            _ => 3,
        });
        let distinct: BTreeSet<&ReputationState> =
            matches.iter().map(|entry| &entry.state).collect();
        let state = if distinct.len() > 1 {
            ReputationState::Suspicious
        } else {
            matches
                .first()
                .map_or(ReputationState::Unknown, |e| e.state.clone())
        };
        let first = matches.first();
        Ok(ReputationResult {
            provider: "local-pasol-reputation".into(),
            provider_version: "0.1.0".into(),
            state,
            confidence: None,
            labels: first.map_or_else(Vec::new, |e| e.labels.clone()),
            reason: first.and_then(|e| e.reason.clone()),
            source: first.and_then(|e| e.source.clone()),
            first_seen: first.map(|e| e.created_at.clone()),
            last_seen: None,
            cache: CacheMetadata {
                hit: !matches.is_empty(),
                stored_at: None,
                expires_at: first.and_then(|e| e.expires_at.clone()),
            },
        })
    }
}

pub fn report(hash: &str, result: ReputationResult) -> Result<ReputationReport, ReputationError> {
    validate_sha256(hash)?;
    Ok(ReputationReport {
        schema_version: REPORT_SCHEMA_VERSION.into(),
        sha256: hash.into(),
        queried_at: now_utc(),
        status: "complete".into(),
        results: vec![result],
        warnings: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn states_round_trip() {
        let states = [
            ReputationState::KnownBenign,
            ReputationState::KnownMalicious,
            ReputationState::Suspicious,
            ReputationState::Unknown,
            ReputationState::Unavailable,
            ReputationState::RateLimited,
            ReputationState::Unauthorized,
            ReputationState::ProviderError,
        ];
        let encoded = serde_json::to_string(&states).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<ReputationState>>(&encoded).unwrap(),
            states
        );
    }
    #[test]
    fn unknown_is_not_benign() {
        let result = LocalStore::empty().lookup(&"a".repeat(64)).unwrap();
        assert_eq!(result.state, ReputationState::Unknown);
    }
}
