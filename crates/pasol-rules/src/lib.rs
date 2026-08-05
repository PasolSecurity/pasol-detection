#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pasol_detection_sdk::{Feature, FeatureReport, FeatureState};
pub use pasol_trust::{KeyStatus, TrustError, TrustedKey, TrustedKeyStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub id: String,
    pub version: String,
    pub feature_schema: String,
    pub rules: Vec<Rule>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub version: u32,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub condition: Expr,
    pub explanation: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expr {
    All {
        all: Vec<Expr>,
    },
    Any {
        any: Vec<Expr>,
    },
    Not {
        not: Box<Expr>,
    },
    Compare {
        feature: String,
        operator: Operator,
        value: Option<Value>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Exists,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
    CountGreaterThan,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_version: u32,
    pub severity: Severity,
    pub confidence: Confidence,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<pasol_detection_sdk::FeatureEvidence>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleReport {
    pub schema_version: String,
    pub engine: String,
    pub engine_version: String,
    pub feature_schema_version: String,
    pub rule_pack_sha256: String,
    pub matches: Vec<RuleMatch>,
    pub not_evaluated: Vec<String>,
    pub warnings: Vec<String>,
}
#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid rule pack: {0}")]
    Invalid(String),
    #[error("feature schema mismatch: {0}")]
    Schema(String),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rule-pack signature or trust failure: {0}")]
    Trust(String),
}

#[derive(Debug, Clone)]
pub struct RuleLimits {
    pub max_rules: usize,
    pub max_expressions: usize,
    pub max_string_length: usize,
    pub max_output_matches: usize,
    pub max_evidence_items: usize,
    pub max_output_bytes: usize,
}
impl Default for RuleLimits {
    fn default() -> Self {
        Self {
            max_rules: 1024,
            max_expressions: 4096,
            max_string_length: 4096,
            max_output_matches: 1024,
            max_evidence_items: 4096,
            max_output_bytes: 1_048_576,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRulePack {
    pub pack: RulePack,
    pub key_id: String,
    pub manifest_sha256: String,
    pub signature_hex: String,
}

pub fn load_pack(bytes: &[u8]) -> Result<RulePack, RuleError> {
    load_pack_with_limits(bytes, &RuleLimits::default())
}

pub fn load_pack_with_limits(bytes: &[u8], limits: &RuleLimits) -> Result<RulePack, RuleError> {
    let pack: RulePack = serde_json::from_slice(bytes)?;
    if pack.rules.is_empty() {
        return Err(RuleError::Invalid("rule pack is empty".into()));
    }
    if pack.rules.len() > limits.max_rules {
        return Err(RuleError::Invalid("rule count exceeds limit".into()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for rule in &pack.rules {
        if !ids.insert(&rule.id) {
            return Err(RuleError::Invalid(format!("duplicate rule id {}", rule.id)));
        }
        validate_depth(&rule.condition, 0)?;
        let encoded =
            serde_json::to_string(rule).map_err(|error| RuleError::Invalid(error.to_string()))?;
        if encoded.len() > limits.max_string_length * 16 {
            return Err(RuleError::Invalid("rule size exceeds limit".into()));
        }
    }
    if !pack.feature_schema.starts_with("1.") {
        return Err(RuleError::Schema(pack.feature_schema));
    }
    Ok(pack)
}

pub fn validate_rule_pack_json(value: &Value) -> Result<(), String> {
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/rule-pack-1.0.0.schema.json"))
            .map_err(|error| error.to_string())?;
    jsonschema::validator_for(&schema)
        .map_err(|error| error.to_string())?
        .validate(value)
        .map_err(|error| error.to_string())
}

pub fn validate_rule_report_json(value: &Value) -> Result<(), String> {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/rule-report-1.0.0.schema.json"
    ))
    .map_err(|error| error.to_string())?;
    jsonschema::validator_for(&schema)
        .map_err(|error| error.to_string())?
        .validate(value)
        .map_err(|error| error.to_string())
}

pub fn verify_signed_pack(
    bytes: &[u8],
    trusted_keys: &std::collections::BTreeMap<String, VerifyingKey>,
    limits: &RuleLimits,
) -> Result<RulePack, RuleError> {
    let signed: SignedRulePack = serde_json::from_slice(bytes)?;
    let pack_bytes = serde_json::to_vec(&signed.pack)?;
    let mut hasher = Sha256::new();
    hasher.update(&pack_bytes);
    let digest = format!("{:x}", hasher.finalize());
    if digest != signed.manifest_sha256 {
        return Err(RuleError::Trust("manifest hash mismatch".into()));
    }
    let key = trusted_keys
        .get(&signed.key_id)
        .ok_or_else(|| RuleError::Trust("unknown signing key".into()))?;
    let signature = decode_hex::<64>(&signed.signature_hex)
        .ok_or_else(|| RuleError::Trust("invalid signature encoding".into()))?;
    key.verify(&pack_bytes, &Signature::from_bytes(&signature))
        .map_err(|_| RuleError::Trust("signature verification failed".into()))?;
    load_pack_with_limits(&pack_bytes, limits)
}

pub fn sign_pack(
    pack: &RulePack,
    key_id: &str,
    signing_key: &ed25519_dalek::SigningKey,
    limits: &RuleLimits,
) -> Result<SignedRulePack, RuleError> {
    let pack_bytes = serde_json::to_vec(pack)?;
    let _ = load_pack_with_limits(&pack_bytes, limits)?;
    let mut hasher = Sha256::new();
    hasher.update(&pack_bytes);
    let signature = ed25519_dalek::Signer::sign(signing_key, &pack_bytes);
    Ok(SignedRulePack {
        pack: pack.clone(),
        key_id: key_id.into(),
        manifest_sha256: format!("{:x}", hasher.finalize()),
        signature_hex: signature
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

pub fn load_unsigned_development_pack(
    bytes: &[u8],
    limits: &RuleLimits,
) -> Result<RulePack, RuleError> {
    load_pack_with_limits(bytes, limits)
}

pub fn load_production_pack(
    bytes: &[u8],
    trusted_keys: &std::collections::BTreeMap<String, VerifyingKey>,
    limits: &RuleLimits,
) -> Result<RulePack, RuleError> {
    verify_signed_pack(bytes, trusted_keys, limits)
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

pub fn evaluate(pack: &RulePack, report: &FeatureReport) -> RuleReport {
    evaluate_with_limits(pack, report, &RuleLimits::default())
}

pub fn evaluate_with_limits(
    pack: &RulePack,
    report: &FeatureReport,
    limits: &RuleLimits,
) -> RuleReport {
    let mut matches = Vec::new();
    let mut not_evaluated = Vec::new();
    let mut warnings = Vec::new();
    if pack.rules.len() > limits.max_rules {
        warnings.push("rule count exceeds evaluation limit".into());
    }
    if pack
        .rules
        .iter()
        .map(|rule| expression_count(&rule.condition))
        .sum::<usize>()
        > limits.max_expressions
    {
        warnings.push("expression count exceeds evaluation limit".into());
    }
    for rule in &pack.rules {
        if matches.len() >= limits.max_output_matches {
            warnings.push("match output limit reached".into());
            break;
        }
        match eval(&rule.condition, &report.features) {
            Some(true) => matches.push(RuleMatch {
                rule_id: rule.id.clone(),
                rule_version: rule.version,
                severity: rule.severity.clone(),
                confidence: rule.confidence.clone(),
                title: rule.title.clone(),
                explanation: rule.explanation.clone(),
                evidence: collect_evidence(&rule.condition, &report.features)
                    .into_iter()
                    .take(limits.max_evidence_items)
                    .collect(),
            }),
            None => not_evaluated.push(rule.id.clone()),
            Some(false) => {}
        }
    }
    let mut hasher = Sha256::new();
    if let Ok(serialized) = serde_json::to_vec(pack) {
        hasher.update(serialized);
    }
    RuleReport {
        schema_version: "1.0.0".into(),
        engine: "pasol-rules".into(),
        engine_version: "0.1.0".into(),
        feature_schema_version: report.schema_version.clone(),
        rule_pack_sha256: format!("{:x}", hasher.finalize()),
        matches,
        not_evaluated,
        warnings,
    }
}

fn expression_count(expr: &Expr) -> usize {
    match expr {
        Expr::All { all } => 1 + all.iter().map(expression_count).sum::<usize>(),
        Expr::Any { any } => 1 + any.iter().map(expression_count).sum::<usize>(),
        Expr::Not { not } => 1 + expression_count(not),
        Expr::Compare { .. } => 1,
    }
}

fn find<'a>(features: &'a [Feature], id: &str) -> Option<&'a Feature> {
    features.iter().find(|f| f.id == id)
}
fn eval(expr: &Expr, features: &[Feature]) -> Option<bool> {
    match expr {
        Expr::All { all } => {
            let mut unknown = false;
            for e in all {
                match eval(e, features) {
                    Some(false) => return Some(false),
                    None => unknown = true,
                    Some(true) => {}
                }
            }
            if unknown { None } else { Some(true) }
        }
        Expr::Any { any } => {
            let mut unknown = false;
            for e in any {
                match eval(e, features) {
                    Some(true) => return Some(true),
                    None => unknown = true,
                    Some(false) => {}
                }
            }
            if unknown { None } else { Some(false) }
        }
        Expr::Not { not } => eval(not, features).map(|value| !value),
        Expr::Compare {
            feature,
            operator,
            value,
        } => {
            if matches!(operator, Operator::Exists) {
                return Some(find(features, feature).is_some());
            }
            let item = find(features, feature)?;
            if !matches!(item.state, FeatureState::Present | FeatureState::Absent) {
                return None;
            }
            let actual = item.value.as_ref();
            Some(match operator {
                Operator::Exists => actual.is_some(),
                Operator::Equals => actual == value.as_ref(),
                Operator::NotEquals => actual != value.as_ref(),
                Operator::Contains => actual
                    .and_then(Value::as_str)
                    .zip(value.as_ref().and_then(Value::as_str))
                    .is_some_and(|(a, b)| a.contains(b)),
                Operator::StartsWith => actual
                    .and_then(Value::as_str)
                    .zip(value.as_ref().and_then(Value::as_str))
                    .is_some_and(|(a, b)| a.starts_with(b)),
                Operator::EndsWith => actual
                    .and_then(Value::as_str)
                    .zip(value.as_ref().and_then(Value::as_str))
                    .is_some_and(|(a, b)| a.ends_with(b)),
                Operator::GreaterThan => numeric(actual, value).is_some_and(|(a, b)| a > b),
                Operator::GreaterThanOrEqual => numeric(actual, value).is_some_and(|(a, b)| a >= b),
                Operator::LessThan => numeric(actual, value).is_some_and(|(a, b)| a < b),
                Operator::LessThanOrEqual => numeric(actual, value).is_some_and(|(a, b)| a <= b),
                Operator::In => value
                    .as_ref()
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        actual.is_some_and(|candidate| items.iter().any(|item| item == candidate))
                    }),
                Operator::NotIn => value
                    .as_ref()
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        actual.is_some_and(|candidate| !items.iter().any(|item| item == candidate))
                    }),
                Operator::CountGreaterThan => actual
                    .and_then(Value::as_array)
                    .zip(value.as_ref().and_then(Value::as_u64))
                    .is_some_and(|(items, count)| items.len() as u64 > count),
            })
        }
    }
}

fn validate_depth(expr: &Expr, depth: usize) -> Result<(), RuleError> {
    if depth > 32 {
        return Err(RuleError::Invalid(
            "rule expression exceeds depth limit".into(),
        ));
    }
    match expr {
        Expr::All { all } => {
            for child in all {
                validate_depth(child, depth + 1)?;
            }
        }
        Expr::Any { any } => {
            for child in any {
                validate_depth(child, depth + 1)?;
            }
        }
        Expr::Not { not } => validate_depth(not, depth + 1)?,
        Expr::Compare { .. } => {}
    }
    Ok(())
}

fn numeric(actual: Option<&Value>, expected: &Option<Value>) -> Option<(f64, f64)> {
    Some((actual?.as_f64()?, expected.as_ref()?.as_f64()?))
}
fn collect_evidence(
    expr: &Expr,
    features: &[Feature],
) -> Vec<pasol_detection_sdk::FeatureEvidence> {
    let mut out = Vec::new();
    match expr {
        Expr::Compare { feature, .. } => {
            if let Some(item) = find(features, feature) {
                out.extend(item.evidence.clone());
            }
        }
        Expr::All { all } => {
            for child in all {
                out.extend(collect_evidence(child, features));
            }
        }
        Expr::Any { any } => {
            for child in any {
                out.extend(collect_evidence(child, features));
            }
        }
        Expr::Not { not } => out.extend(collect_evidence(not, features)),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn fixture_pack() -> RulePack {
        RulePack {
            id: "pasol-starter-rules".into(),
            version: "0.1.0".into(),
            feature_schema: "1.0.0".into(),
            rules: vec![Rule {
                id: "pasol.pe.writable_executable_section".into(),
                version: 1,
                title: "Writable and executable section".into(),
                description: "A PE section is both writable and executable.".into(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                condition: Expr::Compare {
                    feature: "pe.sections.writable_executable.count".into(),
                    operator: Operator::GreaterThan,
                    value: Some(json!(0)),
                },
                explanation: "The feature report contains a writable-and-executable section."
                    .into(),
            }],
        }
    }

    fn signed_fixture() -> (Vec<u8>, SigningKey) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pack = fixture_pack();
        let bytes = serde_json::to_vec(&pack).expect("pack serializes");
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let signed = SignedRulePack {
            pack,
            key_id: "test-key".into(),
            manifest_sha256: format!("{:x}", digest.finalize()),
            signature_hex: hex_encode(&key.sign(&bytes).to_bytes()),
        };
        (
            serde_json::to_vec(&signed).expect("signed pack serializes"),
            key,
        )
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
    #[test]
    fn unknown_is_not_false() {
        let report = FeatureReport {
            schema_version: "1.0.0".into(),
            extractor: "x".into(),
            extractor_version: "x".into(),
            source: pasol_detection_sdk::FeatureSource {
                parser: "p".into(),
                parser_version: "1".into(),
                parser_schema_version: "1".into(),
                sha256: "a".into(),
                file_type: "x".into(),
            },
            status: pasol_detection_sdk::FeatureReportStatus::Complete,
            features: vec![Feature {
                id: "x".into(),
                state: FeatureState::Unknown,
                value: None,
                evidence: vec![],
            }],
            warnings: vec![],
        };
        let pack = RulePack {
            id: "p".into(),
            version: "1".into(),
            feature_schema: "1.0.0".into(),
            rules: vec![Rule {
                id: "r".into(),
                version: 1,
                title: "r".into(),
                description: "".into(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                condition: Expr::Compare {
                    feature: "x".into(),
                    operator: Operator::Equals,
                    value: Some(Value::Bool(true)),
                },
                explanation: "e".into(),
            }],
        };
        assert_eq!(evaluate(&pack, &report).not_evaluated, vec!["r"]);
    }

    #[test]
    fn signed_pack_verifies_and_tampering_fails() {
        let (bytes, key) = signed_fixture();
        let mut trusted = std::collections::BTreeMap::new();
        trusted.insert("test-key".into(), key.verifying_key());
        assert!(load_production_pack(&bytes, &trusted, &RuleLimits::default()).is_ok());
        let mut changed: Value = serde_json::from_slice(&bytes).expect("signed JSON");
        changed["pack"]["id"] = Value::String("changed".into());
        let changed = serde_json::to_vec(&changed).expect("changed JSON");
        assert!(matches!(
            load_production_pack(&changed, &trusted, &RuleLimits::default()),
            Err(RuleError::Trust(_))
        ));
    }

    #[test]
    fn unknown_key_invalid_encoding_and_unsigned_production_are_rejected() {
        let (bytes, key) = signed_fixture();
        let no_keys = std::collections::BTreeMap::new();
        assert!(matches!(
            load_production_pack(&bytes, &no_keys, &RuleLimits::default()),
            Err(RuleError::Trust(_))
        ));
        let mut trusted = std::collections::BTreeMap::new();
        trusted.insert("test-key".into(), key.verifying_key());
        let mut invalid: Value = serde_json::from_slice(&bytes).expect("signed JSON");
        invalid["signature_hex"] = Value::String("bad".into());
        assert!(matches!(
            load_production_pack(
                &serde_json::to_vec(&invalid).expect("invalid JSON"),
                &trusted,
                &RuleLimits::default()
            ),
            Err(RuleError::Trust(_))
        ));
        let unsigned = serde_json::to_vec(&fixture_pack()).expect("pack JSON");
        assert!(load_production_pack(&unsigned, &trusted, &RuleLimits::default()).is_err());
        assert!(load_unsigned_development_pack(&unsigned, &RuleLimits::default()).is_ok());
    }

    #[test]
    fn evaluation_budget_emits_warning() {
        let report = FeatureReport {
            schema_version: "1.0.0".into(),
            extractor: "x".into(),
            extractor_version: "x".into(),
            source: pasol_detection_sdk::FeatureSource {
                parser: "p".into(),
                parser_version: "1".into(),
                parser_schema_version: "1".into(),
                sha256: "a".into(),
                file_type: "x".into(),
            },
            status: pasol_detection_sdk::FeatureReportStatus::Complete,
            features: vec![],
            warnings: vec![],
        };
        let limits = RuleLimits {
            max_expressions: 0,
            ..RuleLimits::default()
        };
        assert!(
            !evaluate_with_limits(&fixture_pack(), &report, &limits)
                .warnings
                .is_empty()
        );
    }

    fn report_for(state: FeatureState, value: Option<Value>) -> FeatureReport {
        FeatureReport {
            schema_version: "1.0.0".into(),
            extractor: "x".into(),
            extractor_version: "0.1.0".into(),
            source: pasol_detection_sdk::FeatureSource {
                parser: "p".into(),
                parser_version: "1".into(),
                parser_schema_version: "1".into(),
                sha256: "a".repeat(64),
                file_type: "pe64".into(),
            },
            status: pasol_detection_sdk::FeatureReportStatus::Complete,
            features: vec![Feature {
                id: "x".into(),
                state,
                value,
                evidence: vec![],
            }],
            warnings: vec![],
        }
    }

    #[test]
    fn operator_state_matrix_preserves_uncertainty() {
        let operators = [
            Operator::Equals,
            Operator::NotEquals,
            Operator::GreaterThan,
            Operator::GreaterThanOrEqual,
            Operator::LessThan,
            Operator::LessThanOrEqual,
            Operator::In,
            Operator::NotIn,
            Operator::Contains,
            Operator::StartsWith,
            Operator::EndsWith,
            Operator::CountGreaterThan,
        ];
        let uncertain = [
            FeatureState::Unknown,
            FeatureState::Truncated,
            FeatureState::NotApplicable,
            FeatureState::Unsupported,
        ];
        for operator in operators {
            for state in uncertain.clone() {
                let pack = RulePack {
                    id: "matrix".into(),
                    version: "1".into(),
                    feature_schema: "1.0.0".into(),
                    rules: vec![Rule {
                        id: "matrix.rule".into(),
                        version: 1,
                        title: "matrix".into(),
                        description: "".into(),
                        severity: Severity::Low,
                        confidence: Confidence::Low,
                        condition: Expr::Compare {
                            feature: "x".into(),
                            operator: operator.clone(),
                            value: Some(json!(1)),
                        },
                        explanation: "matrix".into(),
                    }],
                };
                assert_eq!(
                    evaluate(&pack, &report_for(state, None)).not_evaluated,
                    vec!["matrix.rule"]
                );
            }
        }
        let missing = FeatureReport {
            features: vec![],
            ..report_for(FeatureState::Present, Some(json!(1)))
        };
        let exists = RulePack {
            id: "exists".into(),
            version: "1".into(),
            feature_schema: "1.0.0".into(),
            rules: vec![Rule {
                id: "exists.rule".into(),
                version: 1,
                title: "exists".into(),
                description: "".into(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                condition: Expr::Compare {
                    feature: "missing".into(),
                    operator: Operator::Exists,
                    value: None,
                },
                explanation: "exists".into(),
            }],
        };
        assert!(evaluate(&exists, &missing).not_evaluated.is_empty());
        assert!(evaluate(&exists, &missing).matches.is_empty());
        let wrong_type = RulePack {
            id: "type".into(),
            version: "1".into(),
            feature_schema: "1.0.0".into(),
            rules: vec![Rule {
                id: "type.rule".into(),
                version: 1,
                title: "type".into(),
                description: "".into(),
                severity: Severity::Low,
                confidence: Confidence::Low,
                condition: Expr::Compare {
                    feature: "x".into(),
                    operator: Operator::GreaterThan,
                    value: Some(json!(1)),
                },
                explanation: "type".into(),
            }],
        };
        assert!(
            evaluate(
                &wrong_type,
                &report_for(FeatureState::Present, Some(json!("wrong")))
            )
            .matches
            .is_empty()
        );
    }

    #[test]
    fn golden_rule_reports_validate_and_are_byte_stable() {
        let golden = |name: &str| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/golden/rules")
                .join(name)
        };
        let pack = fixture_pack();
        let mut no_match_report = report_for(FeatureState::Present, Some(json!(false)));
        no_match_report.features[0].id = "pe.sections.writable_executable.count".into();
        let no_match =
            serde_json::to_string(&evaluate(&pack, &no_match_report)).expect("golden serializes");
        assert_eq!(
            format!("{no_match}\n"),
            std::fs::read_to_string(golden("no-match.json")).expect("no-match golden")
        );
        let unknown =
            serde_json::to_string(&evaluate(&pack, &report_for(FeatureState::Unknown, None)))
                .expect("golden serializes");
        assert_eq!(
            format!("{unknown}\n"),
            std::fs::read_to_string(golden("not-evaluated.json")).expect("not-evaluated golden")
        );
        let mut match_report = report_for(FeatureState::Present, Some(json!(1)));
        match_report.features[0].id = "pe.sections.writable_executable.count".into();
        match_report.features[0]
            .evidence
            .push(pasol_detection_sdk::evidence(
                "/metadata/sections",
                "Writable and executable section count",
            ));
        let matched =
            serde_json::to_string(&evaluate(&pack, &match_report)).expect("golden serializes");
        assert_eq!(
            format!("{matched}\n"),
            std::fs::read_to_string(golden("match.json")).expect("match golden")
        );
        let budget = serde_json::to_string(&evaluate_with_limits(
            &pack,
            &no_match_report,
            &RuleLimits {
                max_expressions: 0,
                ..RuleLimits::default()
            },
        ))
        .expect("golden serializes");
        assert_eq!(
            format!("{budget}\n"),
            std::fs::read_to_string(golden("budget-warning.json")).expect("budget golden")
        );
        for name in [
            "no-match.json",
            "not-evaluated.json",
            "match.json",
            "budget-warning.json",
        ] {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(golden(name)).expect("golden file"))
                    .expect("golden JSON");
            validate_rule_report_json(&value).expect("golden validates");
        }
    }
}
