use pasol_patterns::{PATTERN_ENGINE, PATTERN_SCHEMA_VERSION, PatternReport, PatternScanStatus};

fn report() -> PatternReport {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "engine": {"id": "yara-x", "version": "1.19.0"},
        "pattern_pack": {"id": "pasol.test", "version": "0.1.0", "sha256": "a".repeat(64), "signature_state": "development"},
        "input": {"sha256": "b".repeat(64), "size_bytes": 0},
        "status": "completed",
        "matches": [],
        "warnings": [],
        "limits": {"input_bytes": 1, "report_bytes": 1, "matching_rules": 1, "evidence_entries": 1},
        "timing": {"compile_time_ms": 0, "scan_time_ms": 0}
    })).expect("report fixture")
}

#[test]
fn checked_in_contract_schemas_are_valid_documents() {
    for name in [
        "pattern-pack-1.0.0.schema.json",
        "pattern-report-1.0.0.schema.json",
        "pattern-worker-request-1.0.0.schema.json",
        "pattern-worker-response-1.0.0.schema.json",
    ] {
        let text = match name {
            "pattern-pack-1.0.0.schema.json" => {
                include_str!("../../../schemas/pattern-pack-1.0.0.schema.json")
            }
            "pattern-report-1.0.0.schema.json" => {
                include_str!("../../../schemas/pattern-report-1.0.0.schema.json")
            }
            "pattern-worker-request-1.0.0.schema.json" => {
                include_str!("../../../schemas/pattern-worker-request-1.0.0.schema.json")
            }
            _ => include_str!("../../../schemas/pattern-worker-response-1.0.0.schema.json"),
        };
        let value: serde_json::Value = serde_json::from_str(text).expect("schema JSON");
        jsonschema::validator_for(&value).expect("schema compiles");
    }
}

#[test]
fn reports_validate_deterministically_for_every_status() {
    for status in [
        PatternScanStatus::Completed,
        PatternScanStatus::Timeout,
        PatternScanStatus::ResourceLimited,
        PatternScanStatus::WorkerFailed,
        PatternScanStatus::InvalidInput,
        PatternScanStatus::InvalidPack,
        PatternScanStatus::UnsupportedEngine,
        PatternScanStatus::NotEvaluated,
    ] {
        let mut value = report();
        value.status = status;
        value.normalize();
        let first = serde_json::to_vec(&value).expect("serialize");
        let second = serde_json::to_vec(&value).expect("serialize");
        assert_eq!(first, second);
        assert_eq!(value.schema_version, PATTERN_SCHEMA_VERSION);
        assert_eq!(value.engine.id, PATTERN_ENGINE);
        value.to_validated_json().expect("schema-valid report");
    }
}
