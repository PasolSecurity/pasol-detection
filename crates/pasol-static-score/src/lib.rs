#![forbid(unsafe_code)]

use pasol_detection_sdk::{FeatureReport, FeatureState};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct Contribution {
    pub source: String,
    pub id: String,
    pub points: u32,
    pub explanation: String,
}
#[derive(Debug, Serialize)]
pub struct ScoreReport {
    pub schema_version: String,
    pub scorer: String,
    pub scorer_version: String,
    pub score: u32,
    pub maximum: u32,
    pub method: String,
    pub method_version: String,
    pub contributions: Vec<Contribution>,
    pub advisory: bool,
}

pub fn score(report: &FeatureReport) -> ScoreReport {
    let mut contributions = Vec::new();
    add_bool(
        &mut contributions,
        report,
        "pe.sections.writable_executable.count",
        20,
        "Writable and executable sections are present",
    );
    add_bool(
        &mut contributions,
        report,
        "pe.section.entropy.high_count",
        10,
        "One or more sections have high entropy",
    );
    let total = contributions
        .iter()
        .map(|item: &Contribution| item.points)
        .sum::<u32>()
        .min(100);
    ScoreReport {
        schema_version: "1.0.0".into(),
        scorer: "pasol-static-score".into(),
        scorer_version: "0.1.0".into(),
        score: total,
        maximum: 100,
        method: "pasol-static-heuristic".into(),
        method_version: "0.1.0".into(),
        contributions,
        advisory: true,
    }
}
fn add_bool(
    out: &mut Vec<Contribution>,
    report: &FeatureReport,
    id: &str,
    points: u32,
    explanation: &str,
) {
    let Some(feature) = report.features.iter().find(|item| item.id == id) else {
        return;
    };
    if feature.state != FeatureState::Present {
        return;
    }
    let Some(value) = feature.value.as_ref() else {
        return;
    };
    let active = value.as_u64().is_some_and(|value| value > 0) || value.as_bool().unwrap_or(false);
    if active && points > 0 {
        out.push(Contribution {
            source: "feature".into(),
            id: id.into(),
            points,
            explanation: explanation.into(),
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_report_is_zero() {
        let report = FeatureReport {
            schema_version: "1.0.0".into(),
            extractor: "x".into(),
            extractor_version: "x".into(),
            source: pasol_detection_sdk::FeatureSource {
                parser: "p".into(),
                parser_version: "1".into(),
                parser_schema_version: "1".into(),
                sha256: "a".into(),
                file_type: "pe64".into(),
            },
            status: pasol_detection_sdk::FeatureReportStatus::Complete,
            features: vec![],
            warnings: vec![],
        };
        assert_eq!(score(&report).score, 0);
    }
}
