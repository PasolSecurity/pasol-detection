use super::{
    PATTERN_ENGINE, PATTERN_SCHEMA_VERSION, PatternContractError, PatternPackIdentity,
    PatternSignatureState,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use pasol_trust::TrustedKeyStore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PATTERN_LIMITS_PROFILE: &str = "phase-i-default";
pub const PATTERN_METADATA_POLICY: &str = "pasol-pattern-metadata-1";
pub const PATTERN_SIGNATURE_ALGORITHM: &str = "ed25519";
const DOMAIN: &[u8] = b"PASOL\0PATTERN-PACK\0SIGNATURE\0V1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternPackManifest {
    pub schema_version: String,
    pub pack_id: String,
    pub pack_version: String,
    pub engine: String,
    pub engine_version_requirement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<String>,
    pub sources: Vec<PatternSourceManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternSourceManifest {
    pub namespace: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternPackSignature {
    pub schema_version: String,
    pub algorithm: String,
    pub key_id: String,
    pub manifest_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
pub struct PatternPackVerificationLimits {
    pub max_manifest_bytes: usize,
    pub max_signature_bytes: usize,
    pub max_source_files: usize,
    pub max_single_source_bytes: usize,
    pub max_total_source_bytes: usize,
    pub max_path_bytes: usize,
    pub max_namespace_bytes: usize,
    pub max_pack_id_bytes: usize,
}

impl Default for PatternPackVerificationLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 256 * 1024,
            max_signature_bytes: 16 * 1024,
            max_source_files: 64,
            max_single_source_bytes: 1024 * 1024,
            max_total_source_bytes: 4 * 1024 * 1024,
            max_path_bytes: 4096,
            max_namespace_bytes: 256,
            max_pack_id_bytes: 256,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PatternPackBundleInput {
    pub manifest_json: Vec<u8>,
    pub signature_json: Option<Vec<u8>>,
    pub sources: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPatternSource {
    path: String,
    namespace: String,
    sha256: String,
    bytes: Vec<u8>,
}

impl VerifiedPatternSource {
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PatternPackManifest {
    pub fn validate(
        &self,
        limits: &PatternPackVerificationLimits,
    ) -> Result<(), PatternContractError> {
        if self.schema_version != PATTERN_SCHEMA_VERSION {
            return Err(PatternContractError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        if self.pack_id.is_empty() || self.pack_id.len() > limits.max_pack_id_bytes {
            return Err(PatternContractError::Invalid(
                "pack id is invalid or oversized".into(),
            ));
        }
        if semver::Version::parse(&self.pack_version).is_err() {
            return Err(PatternContractError::Invalid("invalid pack version".into()));
        }
        if self.engine != PATTERN_ENGINE {
            return Err(PatternContractError::Invalid(
                "unsupported pattern engine".into(),
            ));
        }
        if semver::VersionReq::parse(&self.engine_version_requirement).is_err() {
            return Err(PatternContractError::Invalid(
                "invalid engine version requirement".into(),
            ));
        }
        if !semver::VersionReq::parse(&self.engine_version_requirement)
            .map_err(|_| {
                PatternContractError::Invalid("invalid engine version requirement".into())
            })?
            .matches(&semver::Version::new(1, 19, 0))
        {
            return Err(PatternContractError::Invalid(
                "engine requirement excludes yara-x 1.19.0".into(),
            ));
        }
        if let Some(policy) = &self.limits_profile
            && policy != PATTERN_LIMITS_PROFILE
        {
            return Err(PatternContractError::Invalid(
                "unknown limits profile".into(),
            ));
        }
        if let Some(policy) = &self.metadata_policy
            && policy != PATTERN_METADATA_POLICY
        {
            return Err(PatternContractError::Invalid(
                "unknown metadata policy".into(),
            ));
        }
        if self.sources.is_empty() || self.sources.len() > limits.max_source_files {
            return Err(PatternContractError::Invalid(
                "source count is invalid".into(),
            ));
        }
        let mut paths = BTreeSet::new();
        for source in &self.sources {
            validate_path(&source.path, limits.max_path_bytes)?;
            if !paths.insert(source.path.to_ascii_lowercase()) {
                return Err(PatternContractError::Invalid(
                    "case-insensitive source collision".into(),
                ));
            }
            if source.namespace.is_empty()
                || source.namespace.len() > limits.max_namespace_bytes
                || source.namespace.chars().any(|c| c.is_control())
            {
                return Err(PatternContractError::Invalid("invalid namespace".into()));
            }
            if source.sha256.len() != 64
                || !source
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(PatternContractError::Invalid("invalid source hash".into()));
            }
        }
        Ok(())
    }
}

pub fn canonical_manifest_bytes(
    manifest: &PatternPackManifest,
) -> Result<Vec<u8>, PatternContractError> {
    manifest.validate(&PatternPackVerificationLimits::default())?;
    let mut normalized = manifest.clone();
    normalized.sources.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.namespace.cmp(&b.namespace))
            .then(a.sha256.cmp(&b.sha256))
    });
    serde_json::to_vec(&normalized).map_err(|e| PatternContractError::Invalid(e.to_string()))
}

pub fn manifest_sha256(manifest: &PatternPackManifest) -> Result<String, PatternContractError> {
    Ok(hex::encode(Sha256::digest(canonical_manifest_bytes(
        manifest,
    )?)))
}

pub fn validate_manifest_json(value: &serde_json::Value) -> Result<(), PatternContractError> {
    validate_schema_document("pattern-pack-1.0.0.schema.json", value)
}

pub fn validate_signature_json(value: &serde_json::Value) -> Result<(), PatternContractError> {
    validate_schema_document("pattern-pack-signature-1.0.0.schema.json", value)
}

pub fn pattern_signature_message(
    key_id: &str,
    canonical_manifest: &[u8],
) -> Result<Vec<u8>, PatternContractError> {
    if key_id.is_empty() || key_id.len() > 256 {
        return Err(PatternContractError::Invalid("invalid key id".into()));
    }
    let key_len = u32::try_from(key_id.len())
        .map_err(|_| PatternContractError::Invalid("key id too long".into()))?;
    let manifest_len = u64::try_from(canonical_manifest.len())
        .map_err(|_| PatternContractError::Invalid("manifest too large".into()))?;
    let mut message =
        Vec::with_capacity(DOMAIN.len() + 4 + key_id.len() + 8 + canonical_manifest.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&key_len.to_be_bytes());
    message.extend_from_slice(key_id.as_bytes());
    message.extend_from_slice(&manifest_len.to_be_bytes());
    message.extend_from_slice(canonical_manifest);
    Ok(message)
}

pub fn sign_pattern_pack(
    manifest: &PatternPackManifest,
    sources: &BTreeMap<String, Vec<u8>>,
    key_id: &str,
    signing_key: &SigningKey,
    limits: &PatternPackVerificationLimits,
) -> Result<PatternPackSignature, PatternContractError> {
    manifest.validate(limits)?;
    validate_manifest_json(
        &serde_json::to_value(manifest)
            .map_err(|e| PatternContractError::Invalid(e.to_string()))?,
    )?;
    if sources.len() != manifest.sources.len() {
        return Err(PatternContractError::Invalid(
            "source set does not match manifest".into(),
        ));
    }
    for source in &manifest.sources {
        let bytes = sources
            .get(&source.path)
            .ok_or_else(|| PatternContractError::Invalid("missing source".into()))?;
        if bytes.len() > limits.max_single_source_bytes
            || bytes.is_empty()
            || std::str::from_utf8(bytes).is_err()
        {
            return Err(PatternContractError::Invalid("invalid source bytes".into()));
        }
        if hex::encode(Sha256::digest(bytes)) != source.sha256 {
            return Err(PatternContractError::Invalid("source hash mismatch".into()));
        }
    }
    let canonical = canonical_manifest_bytes(manifest)?;
    let digest = hex::encode(Sha256::digest(&canonical));
    let signature = signing_key.sign(&pattern_signature_message(key_id, &canonical)?);
    let result = PatternPackSignature {
        schema_version: PATTERN_SCHEMA_VERSION.into(),
        algorithm: PATTERN_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.into(),
        manifest_sha256: digest,
        signature_hex: hex::encode(signature.to_bytes()),
    };
    validate_signature_json(
        &serde_json::to_value(&result).map_err(|e| PatternContractError::Invalid(e.to_string()))?,
    )?;
    Ok(result)
}

pub fn verify_signed_pattern_pack(
    bundle: &PatternPackBundleInput,
    trusted_keys: &TrustedKeyStore,
    supported_engine_version: &semver::Version,
    limits: &PatternPackVerificationLimits,
) -> Result<super::VerifiedPatternPack, PatternContractError> {
    if bundle.manifest_json.len() > limits.max_manifest_bytes {
        return Err(PatternContractError::Invalid(
            "manifest exceeds limit".into(),
        ));
    }
    let manifest_value: serde_json::Value = serde_json::from_slice(&bundle.manifest_json)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    validate_manifest_json(&manifest_value)?;
    let manifest: PatternPackManifest = serde_json::from_value(manifest_value)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    manifest.validate(limits)?;
    let requirement = semver::VersionReq::parse(&manifest.engine_version_requirement)
        .map_err(|_| PatternContractError::Invalid("invalid engine requirement".into()))?;
    if !requirement.matches(supported_engine_version) {
        return Err(PatternContractError::Invalid(
            "engine version is unsupported".into(),
        ));
    }
    if bundle.sources.len() != manifest.sources.len() {
        return Err(PatternContractError::Invalid(
            "source set does not match manifest".into(),
        ));
    }
    let mut verified_sources = Vec::with_capacity(manifest.sources.len());
    let mut total = 0usize;
    for source in &manifest.sources {
        let bytes = bundle
            .sources
            .get(&source.path)
            .ok_or_else(|| PatternContractError::Invalid("missing source".into()))?;
        if bytes.len() > limits.max_single_source_bytes || bytes.is_empty() {
            return Err(PatternContractError::Invalid(
                "source exceeds limit or is empty".into(),
            ));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| PatternContractError::Invalid("source is not UTF-8".into()))?;
        if has_forbidden_source_control(text) {
            return Err(PatternContractError::Invalid(
                "source contains forbidden controls".into(),
            ));
        }
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| PatternContractError::Invalid("source size overflow".into()))?;
        if total > limits.max_total_source_bytes {
            return Err(PatternContractError::Invalid(
                "source bundle exceeds limit".into(),
            ));
        }
        let digest = hex::encode(Sha256::digest(bytes));
        if digest != source.sha256 {
            return Err(PatternContractError::Invalid("source hash mismatch".into()));
        }
        verified_sources.push(VerifiedPatternSource {
            path: source.path.clone(),
            namespace: source.namespace.clone(),
            sha256: digest,
            bytes: bytes.clone(),
        });
    }
    let signature_json = bundle
        .signature_json
        .as_ref()
        .ok_or_else(|| PatternContractError::Invalid("production signature is required".into()))?;
    if signature_json.len() > limits.max_signature_bytes {
        return Err(PatternContractError::Invalid(
            "signature exceeds limit".into(),
        ));
    }
    let signature_value: serde_json::Value = serde_json::from_slice(signature_json)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    validate_signature_json(&signature_value)?;
    let signature: PatternPackSignature = serde_json::from_value(signature_value)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    if signature.schema_version != PATTERN_SCHEMA_VERSION
        || signature.algorithm != PATTERN_SIGNATURE_ALGORITHM
        || signature.signature_hex.len() != 128
        || !signature
            .signature_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(PatternContractError::Invalid(
            "invalid detached signature".into(),
        ));
    }
    let canonical = canonical_manifest_bytes(&manifest)?;
    let digest = hex::encode(Sha256::digest(&canonical));
    if digest != signature.manifest_sha256 {
        return Err(PatternContractError::Invalid(
            "manifest hash mismatch".into(),
        ));
    }
    let signature_bytes = hex::decode(&signature.signature_hex)
        .map_err(|_| PatternContractError::Invalid("invalid signature encoding".into()))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| PatternContractError::Invalid("invalid signature length".into()))?;
    let resolved = trusted_keys
        .resolve_for_verification(&signature.key_id)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    resolved
        .verifying_key
        .verify(
            &pattern_signature_message(&signature.key_id, &canonical)?,
            &Signature::from_bytes(&signature_array),
        )
        .map_err(|_| PatternContractError::Invalid("signature verification failed".into()))?;
    let identity = PatternPackIdentity {
        id: manifest.pack_id.clone(),
        version: manifest.pack_version.clone(),
        sha256: digest,
        signature_state: PatternSignatureState::Verified,
    };
    Ok(super::VerifiedPatternPack::from_verified_parts(
        super::PatternPackReference { identity },
        manifest,
        verified_sources,
        resolved.key_id,
        resolved.status,
    ))
}

fn validate_path(path: &str, max: usize) -> Result<(), PatternContractError> {
    if path.is_empty()
        || path.len() > max
        || path.contains('\\')
        || path.contains(':')
        || path.starts_with('/')
        || path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(' ')
                || part.ends_with('.')
        })
        || !path.ends_with(".yar") && !path.ends_with(".yara")
        || path.chars().any(|c| c.is_control())
    {
        return Err(PatternContractError::Invalid(
            "invalid portable source path".into(),
        ));
    }
    Ok(())
}

fn has_forbidden_source_control(source: &str) -> bool {
    let bytes = source.as_bytes();
    for (index, character) in source.char_indices() {
        if character == '\r' {
            if bytes.get(index + 1) != Some(&b'\n') {
                return true;
            }
        } else if character == '\0' || (character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return true;
        }
    }
    false
}

fn validate_schema_document(
    name: &str,
    value: &serde_json::Value,
) -> Result<(), PatternContractError> {
    let schema_text = match name {
        "pattern-pack-1.0.0.schema.json" => {
            include_str!("../../../schemas/pattern-pack-1.0.0.schema.json")
        }
        "pattern-pack-signature-1.0.0.schema.json" => {
            include_str!("../../../schemas/pattern-pack-signature-1.0.0.schema.json")
        }
        _ => {
            return Err(PatternContractError::Invalid(
                "unknown pattern schema".into(),
            ));
        }
    };
    let schema: serde_json::Value = serde_json::from_str(schema_text)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?;
    jsonschema::validator_for(&schema)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))?
        .validate(value)
        .map_err(|e| PatternContractError::Invalid(e.to_string()))
}
