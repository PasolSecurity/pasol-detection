#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use pasol_detection_sdk::{
    FeatureExtractor, FeatureReport, ParserReport, validate_feature_report_json,
};
use pasol_features::PeFeatureExtractor;
use pasol_rules::{evaluate, load_pack, validate_rule_pack_json, validate_rule_report_json};
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_json(path: &str) -> Value {
    let bytes = std::fs::read(root().join(path)).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn schema_and_golden_drift_gate() {
    let pack_value = read_json("rule-packs/pasol-starter.json");
    validate_rule_pack_json(&pack_value).unwrap();
    load_pack(serde_json::to_vec(&pack_value).unwrap().as_slice()).unwrap();

    for parser_path in [
        "fixtures/pe32-parser-report.json",
        "fixtures/pe64-parser-report.json",
    ] {
        let parser: ParserReport = serde_json::from_value(read_json(parser_path)).unwrap();
        let report = PeFeatureExtractor.extract(&parser).unwrap();
        let value = serde_json::to_value(&report).unwrap();
        validate_feature_report_json(&value).unwrap();
    }

    for golden in [
        "fixtures/golden/rules/match.json",
        "fixtures/golden/rules/no-match.json",
        "fixtures/golden/rules/not-evaluated.json",
        "fixtures/golden/rules/budget-warning.json",
    ] {
        validate_rule_report_json(&read_json(golden)).unwrap();
    }
}

#[test]
fn starter_rule_positive_and_negative_fixtures() {
    let pack_value = read_json("rule-packs/pasol-starter.json");
    let pack = load_pack(serde_json::to_vec(&pack_value).unwrap().as_slice()).unwrap();
    for (path, expected_match) in [
        ("fixtures/rules/starter-positive-feature.json", true),
        ("fixtures/rules/starter-negative-feature.json", false),
    ] {
        let value = read_json(path);
        validate_feature_report_json(&value).unwrap();
        let report: FeatureReport = serde_json::from_value(value).unwrap();
        let output = evaluate(&pack, &report);
        validate_rule_report_json(&serde_json::to_value(&output).unwrap()).unwrap();
        assert_eq!(!output.matches.is_empty(), expected_match, "fixture {path}");
    }
}
