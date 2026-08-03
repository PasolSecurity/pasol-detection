#![forbid(unsafe_code)]

use pasol_detection_sdk::{Feature, FeatureReport, FeatureState};
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
}

pub fn load_pack(bytes: &[u8]) -> Result<RulePack, RuleError> {
    let pack: RulePack = serde_json::from_slice(bytes)?;
    if pack.rules.is_empty() {
        return Err(RuleError::Invalid("rule pack is empty".into()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for rule in &pack.rules {
        if !ids.insert(&rule.id) {
            return Err(RuleError::Invalid(format!("duplicate rule id {}", rule.id)));
        }
    }
    if !pack.feature_schema.starts_with("1.") {
        return Err(RuleError::Schema(pack.feature_schema));
    }
    Ok(pack)
}

pub fn evaluate(pack: &RulePack, report: &FeatureReport) -> RuleReport {
    let mut matches = Vec::new();
    let mut not_evaluated = Vec::new();
    for rule in &pack.rules {
        match eval(&rule.condition, &report.features) {
            Some(true) => matches.push(RuleMatch {
                rule_id: rule.id.clone(),
                rule_version: rule.version,
                severity: rule.severity.clone(),
                confidence: rule.confidence.clone(),
                title: rule.title.clone(),
                explanation: rule.explanation.clone(),
                evidence: collect_evidence(&rule.condition, &report.features),
            }),
            None => not_evaluated.push(rule.id.clone()),
            Some(false) => {}
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(pack).unwrap_or_default());
    RuleReport {
        schema_version: "1.0.0".into(),
        engine: "pasol-rules".into(),
        engine_version: "0.1.0".into(),
        feature_schema_version: report.schema_version.clone(),
        rule_pack_sha256: format!("{:x}", hasher.finalize()),
        matches,
        not_evaluated,
        warnings: Vec::new(),
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
            })
        }
    }
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
}
