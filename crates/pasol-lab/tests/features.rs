#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use pasol_detection_sdk::{
    FeatureExtractor, FeatureReportStatus, FeatureState, ParserReport, validate_feature_report_json,
};
use pasol_features::PeFeatureExtractor;
use serde_json::Value;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json(path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(root().join(path)).unwrap()).unwrap()
}

fn feature_report(path: &str) -> pasol_detection_sdk::FeatureReport {
    let parser: ParserReport = serde_json::from_value(json(path)).unwrap();
    PeFeatureExtractor.extract(&parser).unwrap()
}

#[test]
fn feature_goldens_are_schema_valid_and_byte_stable() {
    for (parser, golden) in [
        (
            "fixtures/pe32-parser-report.json",
            "fixtures/golden/features/pe32.json",
        ),
        (
            "fixtures/pe64-parser-report.json",
            "fixtures/golden/features/pe64.json",
        ),
        (
            "fixtures/pe64-partial-parser-report.json",
            "fixtures/golden/features/pe64-partial.json",
        ),
    ] {
        let report = feature_report(parser);
        let value = serde_json::to_value(&report).unwrap();
        validate_feature_report_json(&value).unwrap();
        let expected = format!("{}\n", serde_json::to_string(&report).unwrap());
        assert_eq!(
            std::fs::read_to_string(root().join(golden)).unwrap(),
            expected,
            "{golden}"
        );
        assert!(expected.contains("\"features\":[{"));
        assert!(!expected.contains("C:\\\\"));
    }
    assert_eq!(
        feature_report("fixtures/pe64-partial-parser-report.json").status,
        FeatureReportStatus::Partial
    );
}

#[test]
fn catalog_matrix_covers_positive_negative_and_uncertain_states() {
    let complete = feature_report("fixtures/pe64-parser-report.json");
    let ids: Vec<&str> = complete
        .features
        .iter()
        .map(|feature| feature.id.as_str())
        .collect();
    for required in [
        "file.size.bytes",
        "file.type",
        "file.parser.partial",
        "file.parser.warning_count",
        "file.sha256.present",
        "pe.architecture",
        "pe.machine.raw",
        "pe.subsystem",
        "pe.entry_point.rva",
        "pe.image_base",
        "pe.sections.count",
        "pe.sections.writable.count",
        "pe.sections.executable.count",
        "pe.sections.writable_executable.count",
        "pe.section.names",
        "pe.section.entropy.maximum",
        "pe.section.entropy.high_count",
        "pe.imports.dll_count",
        "pe.imports.symbol_count",
        "pe.exports.count",
        "pe.exports.named_count",
        "pe.resources.count",
        "pe.debug.present",
        "pe.version.present",
        "pe.certificate_table.present",
        "pe.certificate_table.pkcs7_present",
    ] {
        assert!(
            ids.contains(&required),
            "missing catalog feature {required}"
        );
    }
    let writable_exec = complete
        .features
        .iter()
        .find(|feature| feature.id == "pe.sections.writable_executable.count")
        .unwrap();
    assert_eq!(writable_exec.state, FeatureState::Present);
    assert_eq!(writable_exec.value, Some(serde_json::json!(0)));

    let mut missing_entropy: Value = json("fixtures/pe64-parser-report.json");
    missing_entropy["metadata"]["sections"][0]
        .as_object_mut()
        .unwrap()
        .remove("entropy");
    let report: ParserReport = serde_json::from_value(missing_entropy).unwrap();
    let extracted = PeFeatureExtractor.extract(&report).unwrap();
    let entropy = extracted
        .features
        .iter()
        .find(|feature| feature.id == "pe.section.entropy.maximum")
        .unwrap();
    assert_eq!(entropy.state, FeatureState::Unknown);

    let mut unsupported: Value = json("fixtures/pe64-parser-report.json");
    unsupported["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("imports");
    let report: ParserReport = serde_json::from_value(unsupported).unwrap();
    let extracted = PeFeatureExtractor.extract(&report).unwrap();
    let imports = extracted
        .features
        .iter()
        .find(|feature| feature.id == "pe.imports.dll_count")
        .unwrap();
    assert_eq!(imports.state, FeatureState::Unsupported);

    let partial = feature_report("fixtures/pe64-partial-parser-report.json");
    assert_eq!(partial.status, FeatureReportStatus::Partial);
    assert!(
        partial
            .warnings
            .iter()
            .any(|warning| warning.contains("limit"))
    );
}

#[test]
fn unsupported_parser_is_rejected_without_fallback() {
    let mut value = json("fixtures/pe64-parser-report.json");
    value["parser"] = serde_json::json!("unknown-parser");
    let report: ParserReport = serde_json::from_value(value).unwrap();
    assert!(!PeFeatureExtractor.supports(
        &report.parser,
        &report.schema_version,
        &report.file_type
    ));
    assert!(PeFeatureExtractor.extract(&report).is_err());
}
