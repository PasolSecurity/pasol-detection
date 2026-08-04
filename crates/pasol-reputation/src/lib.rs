#![forbid(unsafe_code)]

use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fs, io::Write, path::Path, str::FromStr};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339, macros::format_description};

pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";
pub const STORE_SCHEMA_VERSION: &str = "1.0.0";
pub const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256(String);

impl Sha256 {
    pub fn parse(value: &str) -> Result<Self, ReputationError> {
        validate_sha256(value)?;
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Sha256 {
    type Err = ReputationError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for Sha256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> String;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> String {
        canonical_timestamp(OffsetDateTime::now_utc())
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
    }
}

#[derive(Debug, Clone)]
pub struct FixedClock(pub String);
impl Clock for FixedClock {
    fn now(&self) -> String {
        OffsetDateTime::parse(&self.0, &Rfc3339)
            .ok()
            .and_then(|value| canonical_timestamp(value).ok())
            .unwrap_or_else(|| self.0.clone())
    }
}

pub struct ReputationContext<'a> {
    pub clock: &'a dyn Clock,
    pub query_type: &'static str,
}

pub trait ReputationProvider: Send + Sync {
    fn descriptor(&self) -> &ProviderDescriptor;
    fn lookup_hash(
        &self,
        sha256: &Sha256,
        context: &ReputationContext<'_>,
    ) -> Result<ReputationResult, ReputationError>;
}

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
    #[error("resource limit exceeded: {0}")]
    Limit(String),
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
    SystemClock.now()
}

impl LocalStore {
    pub fn empty() -> Self {
        Self {
            schema_version: STORE_SCHEMA_VERSION.into(),
            entries: Vec::new(),
        }
    }
    pub fn load(path: &Path) -> Result<Self, ReputationError> {
        let metadata = fs::metadata(path).map_err(|e| ReputationError::Io(e.to_string()))?;
        if metadata.len() > MAX_STORE_BYTES as u64 {
            return Err(ReputationError::Limit("store input exceeds 8 MiB".into()));
        }
        let bytes = fs::read(path).map_err(|e| ReputationError::Io(e.to_string()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        validate_store_json(&value).map_err(ReputationError::Schema)?;
        let store: Self = serde_json::from_value(value)
            .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        store.validate_entries()?;
        Ok(store)
    }
    pub fn save_atomic(&self, path: &Path) -> Result<(), ReputationError> {
        let mut ordered = self.clone();
        ordered.sort_entries();
        ordered.validate_entries()?;
        let value = serde_json::to_value(&ordered)
            .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        validate_store_json(&value).map_err(ReputationError::Schema)?;
        let bytes = serde_json::to_vec_pretty(&value)
            .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        if bytes.len() > MAX_STORE_BYTES {
            return Err(ReputationError::Limit("store output exceeds 8 MiB".into()));
        }
        let mut file =
            AtomicWriteFile::open(path).map_err(|e| ReputationError::Io(e.to_string()))?;
        file.write_all(&bytes)
            .map_err(|e| ReputationError::Io(e.to_string()))?;
        file.commit()
            .map_err(|e| ReputationError::Io(e.to_string()))?;
        let reopened = Self::load(path)?;
        if reopened != ordered {
            return Err(ReputationError::InvalidStore(
                "post-write validation mismatch".into(),
            ));
        }
        Ok(())
    }
    pub fn import_merge(&mut self, input: &Path) -> Result<(), ReputationError> {
        let metadata = fs::metadata(input).map_err(|e| ReputationError::Io(e.to_string()))?;
        if metadata.len() > MAX_STORE_BYTES as u64 {
            return Err(ReputationError::Limit("import exceeds 8 MiB".into()));
        }
        let value: Value = serde_json::from_slice(
            &fs::read(input).map_err(|e| ReputationError::Io(e.to_string()))?,
        )
        .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        validate_store_json(&value).map_err(ReputationError::Schema)?;
        let incoming: Self = serde_json::from_value(value)
            .map_err(|e| ReputationError::InvalidStore(e.to_string()))?;
        incoming.validate_entries()?;
        let mut candidate = self.clone();
        for entry in incoming.entries {
            if candidate.entries.iter().any(|existing| existing == &entry) {
                return Err(ReputationError::InvalidStore(
                    "exact duplicate record".into(),
                ));
            }
            candidate.entries.push(entry);
        }
        candidate.sort_entries();
        candidate.validate_entries()?;
        *self = candidate;
        Ok(())
    }
    pub fn export(&self, output: &Path) -> Result<(), ReputationError> {
        self.save_atomic(output)
    }
    fn validate_entries(&self) -> Result<(), ReputationError> {
        if self.entries.len() > 10_000 {
            return Err(ReputationError::Limit("too many records".into()));
        }
        for entry in &self.entries {
            if !matches!(
                entry.state,
                ReputationState::KnownBenign
                    | ReputationState::KnownMalicious
                    | ReputationState::Suspicious
            ) {
                return Err(ReputationError::InvalidStore(
                    "local entries must be benign, malicious, or suspicious".into(),
                ));
            }
            validate_sha256(&entry.sha256)?;
            validate_timestamp(&entry.created_at)?;
            if let Some(expiry) = &entry.expires_at {
                validate_timestamp(expiry)?;
            }
            if entry.labels.len() > 32 || entry.labels.iter().any(|label| label.len() > 128) {
                return Err(ReputationError::Limit("labels exceed limits".into()));
            }
            if entry
                .reason
                .as_ref()
                .is_some_and(|reason| reason.len() > 4096)
                || entry
                    .source
                    .as_ref()
                    .is_some_and(|source| source.len() > 1024)
            {
                return Err(ReputationError::Limit("metadata exceeds limits".into()));
            }
        }
        Ok(())
    }
    fn sort_entries(&mut self) {
        self.entries.sort_by(|a, b| {
            a.sha256
                .cmp(&b.sha256)
                .then(a.created_at.cmp(&b.created_at))
                .then(a.state.cmp(&b.state))
                .then(a.source.cmp(&b.source))
                .then(a.reason.cmp(&b.reason))
        });
    }
    pub fn lookup(&self, hash: &str) -> Result<ReputationResult, ReputationError> {
        self.lookup_at(hash, &SystemClock)
    }
    pub fn lookup_at(
        &self,
        hash: &str,
        clock: &dyn Clock,
    ) -> Result<ReputationResult, ReputationError> {
        validate_sha256(hash)?;
        let mut matches: Vec<&ReputationEntry> = self
            .entries
            .iter()
            .filter(|e| {
                e.enabled
                    && e.sha256 == hash
                    && e.expires_at
                        .as_deref()
                        .is_none_or(|expiry| expiry > clock.now().as_str())
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
                hit: false,
                stored_at: None,
                expires_at: first.and_then(|e| e.expires_at.clone()),
            },
        })
    }
}

pub struct LocalReputationProvider {
    pub store: LocalStore,
    pub descriptor: ProviderDescriptor,
}
impl LocalReputationProvider {
    pub fn new(store: LocalStore) -> Self {
        Self {
            store,
            descriptor: ProviderDescriptor {
                id: "local-pasol-reputation".into(),
                name: "Local Pasol reputation".into(),
                version: "0.1.0".into(),
                offline: true,
                authentication_required: false,
            },
        }
    }
}
impl ReputationProvider for LocalReputationProvider {
    fn descriptor(&self) -> &ProviderDescriptor {
        &self.descriptor
    }
    fn lookup_hash(
        &self,
        sha256: &Sha256,
        context: &ReputationContext<'_>,
    ) -> Result<ReputationResult, ReputationError> {
        self.store.lookup_at(sha256.as_str(), context.clock)
    }
}

fn validate_timestamp(value: &str) -> Result<(), ReputationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| ReputationError::InvalidStore(format!("invalid UTC timestamp: {value}")))
}

fn canonical_timestamp(value: OffsetDateTime) -> Result<String, time::error::Format> {
    value.format(&format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second]Z"
    ))
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
    #[test]
    fn fixed_clock_ignores_expired_entries_and_provider_has_offline_descriptor() {
        let store = LocalStore {
            schema_version: STORE_SCHEMA_VERSION.into(),
            entries: vec![ReputationEntry {
                sha256: "a".repeat(64),
                state: ReputationState::KnownBenign,
                reason: Some("expired".into()),
                source: Some("fixture".into()),
                labels: Vec::new(),
                created_at: "2026-01-01T00:00:00Z".into(),
                expires_at: Some("2026-01-02T00:00:00Z".into()),
                enabled: true,
            }],
        };
        let clock = FixedClock("2026-01-03T00:00:00Z".into());
        assert_eq!(
            store.lookup_at(&"a".repeat(64), &clock).unwrap().state,
            ReputationState::Unknown
        );
        let provider = LocalReputationProvider::new(store);
        assert!(provider.descriptor().offline);
        let sha = Sha256::parse(&"a".repeat(64)).unwrap();
        let context = ReputationContext {
            clock: &clock,
            query_type: "sha256",
        };
        assert_eq!(
            provider.lookup_hash(&sha, &context).unwrap().state,
            ReputationState::Unknown
        );
    }
}
