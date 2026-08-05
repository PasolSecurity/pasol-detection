#![forbid(unsafe_code)]

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use thiserror::Error;

pub const TRUST_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported trust-store schema: {0}")]
    Schema(String),
    #[error("invalid trust key: {0}")]
    Invalid(String),
    #[error("unknown trust key: {0}")]
    UnknownKey(String),
    #[error("revoked trust key: {0}")]
    RevokedKey(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKeyStore {
    pub schema_version: String,
    pub keys: Vec<TrustedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
    pub status: KeyStatus,
    pub trusted_from: String,
    pub revoked_at: Option<String>,
    pub replacement_key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Debug, Clone)]
pub struct ResolvedTrustedKey {
    pub key_id: String,
    pub status: KeyStatus,
    pub verifying_key: VerifyingKey,
}

impl TrustedKeyStore {
    pub fn empty() -> Self {
        Self {
            schema_version: TRUST_SCHEMA_VERSION.into(),
            keys: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), TrustError> {
        if self.schema_version != TRUST_SCHEMA_VERSION {
            return Err(TrustError::Schema(self.schema_version.clone()));
        }
        let mut ids = BTreeSet::new();
        for key in &self.keys {
            if key.key_id.is_empty() || key.key_id.len() > 256 || !ids.insert(&key.key_id) {
                return Err(TrustError::Invalid("duplicate or invalid key id".into()));
            }
            if key.algorithm != "ed25519" {
                return Err(TrustError::Invalid("unsupported key algorithm".into()));
            }
            decode_hex::<32>(&key.public_key_hex)
                .ok_or_else(|| TrustError::Invalid(format!("invalid public key {}", key.key_id)))?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, TrustError> {
        let value: Self = serde_json::from_slice(
            &std::fs::read(path).map_err(|error| TrustError::Io(error.to_string()))?,
        )?;
        value.validate()?;
        Ok(value)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<(), TrustError> {
        self.validate()?;
        let parent = path
            .parent()
            .ok_or_else(|| TrustError::Io("key-store path has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(|error| TrustError::Io(error.to_string()))?;
        let temp = path.with_extension("tmp");
        let data = serde_json::to_vec_pretty(self)?;
        std::fs::write(&temp, data).map_err(|error| TrustError::Io(error.to_string()))?;
        std::fs::rename(&temp, path).map_err(|error| TrustError::Io(error.to_string()))
    }

    pub fn add(&mut self, key: TrustedKey) -> Result<(), TrustError> {
        if self.keys.iter().any(|item| item.key_id == key.key_id) {
            return Err(TrustError::Invalid("duplicate key id".into()));
        }
        self.keys.push(key);
        self.validate()
    }

    pub fn revoke(&mut self, key_id: &str, timestamp: String) -> Result<(), TrustError> {
        let key = self
            .keys
            .iter_mut()
            .find(|item| item.key_id == key_id)
            .ok_or_else(|| TrustError::UnknownKey(key_id.into()))?;
        key.status = KeyStatus::Revoked;
        key.revoked_at = Some(timestamp);
        Ok(())
    }

    pub fn remove(&mut self, key_id: &str) -> Result<(), TrustError> {
        let before = self.keys.len();
        self.keys.retain(|item| item.key_id != key_id);
        if before == self.keys.len() {
            return Err(TrustError::UnknownKey(key_id.into()));
        }
        Ok(())
    }

    pub fn resolve_for_verification(&self, key_id: &str) -> Result<ResolvedTrustedKey, TrustError> {
        let key = self
            .keys
            .iter()
            .find(|item| item.key_id == key_id)
            .ok_or_else(|| TrustError::UnknownKey(key_id.into()))?;
        if key.status == KeyStatus::Revoked {
            return Err(TrustError::RevokedKey(key_id.into()));
        }
        if key.algorithm != "ed25519" {
            return Err(TrustError::Invalid("unsupported key algorithm".into()));
        }
        let bytes = decode_hex::<32>(&key.public_key_hex)
            .ok_or_else(|| TrustError::Invalid(format!("invalid public key {key_id}")))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| TrustError::Invalid(format!("invalid public key {key_id}")))?;
        Ok(ResolvedTrustedKey {
            key_id: key.key_id.clone(),
            status: key.status,
            verifying_key,
        })
    }

    pub fn verifying_keys(&self) -> Result<BTreeMap<String, VerifyingKey>, TrustError> {
        self.validate()?;
        self.keys
            .iter()
            .filter(|key| key.status != KeyStatus::Revoked)
            .map(|key| {
                self.resolve_for_verification(&key.key_id)
                    .map(|resolved| (resolved.key_id, resolved.verifying_key))
            })
            .collect()
    }
}

fn decode_hex<const N: usize>(input: &str) -> Option<[u8; N]> {
    if input.len() != N * 2 {
        return None;
    }
    let mut output = [0u8; N];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(output)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
