use pasol_patterns::{
    PATTERN_ENGINE, PATTERN_SCHEMA_VERSION, PatternInput, PatternLimits, PatternPackIdentity,
    PatternPackReference, PatternReport, PatternScanRequest, PatternScanStatus,
    PatternSignatureState, PatternWorkerRequest,
};
use sha2::Digest;

fn report() -> PatternReport {
    serde_json::from_value(serde_json::json!({
        "schema_version": "1.0.0",
        "engine": {"id": "yara-x", "version": "1.19.0"},
        "pattern_pack": {"id": "pasol.test", "version": "0.1.0", "sha256": "a".repeat(64), "signature_state": "development"},
        "input": {"sha256": "b".repeat(64), "size_bytes": 0},
        "status": "completed",
        "matches": [],
        "warnings": [],
        "limits": {"input_bytes": 1, "report_bytes": 4096, "matching_rules": 1, "evidence_entries": 1, "matches_per_pattern": 1, "compiler_warnings": 1, "locations_per_rule": 1},
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

#[test]
fn worker_payload_identity_and_source_bounds_are_enforced() {
    let payload = b"hello";
    let input_sha = hex::encode(sha2::Sha256::digest(payload));
    let reference = PatternPackReference {
        identity: PatternPackIdentity {
            id: "pasol.test".into(),
            version: "0.1.0".into(),
            sha256: "a".repeat(64),
            signature_state: PatternSignatureState::Development,
        },
    };
    let request = PatternScanRequest {
        schema_version: PATTERN_SCHEMA_VERSION.into(),
        input: PatternInput {
            sha256: input_sha.clone(),
            size_bytes: payload.len() as u64,
            file_type: None,
        },
        pack: reference,
        limits: PatternLimits::default(),
    };
    let worker = PatternWorkerRequest {
        schema_version: PATTERN_SCHEMA_VERSION.into(),
        request,
        input_size: payload.len() as u64,
        input_sha256: input_sha,
        payload_length: payload.len() as u64,
        rule_sources: [(
            "rules/test.yar".into(),
            "rule test { condition: true }".into(),
        )]
        .into_iter()
        .collect(),
    };
    assert!(worker.validate().is_ok());
    assert!(worker.bind_payload(payload).is_ok());
    assert!(worker.bind_payload(b"bad").is_err());
}

#[test]
fn rule_source_line_endings_follow_yara_text_policy() {
    let payload = b"hello";
    let input_sha = hex::encode(sha2::Sha256::digest(payload));
    for source in [
        "rule test {\n\tcondition: true\n}",
        "rule test {\r\n\tcondition: true\r\n}",
    ] {
        let worker = worker_request_for_source(input_sha.clone(), payload.len(), source);
        assert!(
            worker.validate().is_ok(),
            "source should be accepted: {source:?}"
        );
    }
    for source in [
        "rule test {\r condition: true }",
        "rule test {\0 condition: true }",
        "rule test {\u{000b} condition: true }",
    ] {
        let worker = worker_request_for_source(input_sha.clone(), payload.len(), source);
        assert!(
            worker.validate().is_err(),
            "source should be rejected: {source:?}"
        );
    }
}

fn worker_request_for_source(
    input_sha: String,
    payload_len: usize,
    source: &str,
) -> PatternWorkerRequest {
    let reference = PatternPackReference {
        identity: PatternPackIdentity {
            id: "pasol.test".into(),
            version: "0.1.0".into(),
            sha256: "a".repeat(64),
            signature_state: PatternSignatureState::Development,
        },
    };
    PatternWorkerRequest {
        schema_version: PATTERN_SCHEMA_VERSION.into(),
        request: PatternScanRequest {
            schema_version: PATTERN_SCHEMA_VERSION.into(),
            input: PatternInput {
                sha256: input_sha.clone(),
                size_bytes: payload_len as u64,
                file_type: None,
            },
            pack: reference,
            limits: PatternLimits::default(),
        },
        input_size: payload_len as u64,
        input_sha256: input_sha,
        payload_length: payload_len as u64,
        rule_sources: [("rules/test.yar".into(), source.into())]
            .into_iter()
            .collect(),
    }
}

#[test]
fn checked_in_pattern_goldens_are_schema_and_semantic_valid() {
    let reports = [
        "report-completed-no-match.json",
        "report-completed-match.json",
        "report-timeout.json",
        "report-resource-limited.json",
        "report-worker-failed.json",
        "report-invalid-input.json",
        "report-invalid-pack.json",
        "report-unsupported-engine.json",
        "report-not-evaluated.json",
    ];
    for name in reports {
        let text = match name {
            "report-completed-no-match.json" => {
                include_str!("../../../fixtures/golden/patterns/report-completed-no-match.json")
            }
            "report-completed-match.json" => {
                include_str!("../../../fixtures/golden/patterns/report-completed-match.json")
            }
            "report-timeout.json" => {
                include_str!("../../../fixtures/golden/patterns/report-timeout.json")
            }
            "report-resource-limited.json" => {
                include_str!("../../../fixtures/golden/patterns/report-resource-limited.json")
            }
            "report-worker-failed.json" => {
                include_str!("../../../fixtures/golden/patterns/report-worker-failed.json")
            }
            "report-invalid-input.json" => {
                include_str!("../../../fixtures/golden/patterns/report-invalid-input.json")
            }
            "report-invalid-pack.json" => {
                include_str!("../../../fixtures/golden/patterns/report-invalid-pack.json")
            }
            "report-unsupported-engine.json" => {
                include_str!("../../../fixtures/golden/patterns/report-unsupported-engine.json")
            }
            _ => include_str!("../../../fixtures/golden/patterns/report-not-evaluated.json"),
        };
        let value: serde_json::Value = serde_json::from_str(text).expect("golden JSON");
        let report = PatternReport::from_validated_json(&value).expect("valid pattern golden");
        assert_eq!(canonical_json(&report), text.as_bytes());
    }
}

#[test]
fn request_and_response_goldens_round_trip() {
    let scan: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/golden/patterns/scan-request-valid.json"
    ))
    .expect("scan golden");
    let scan_request = PatternScanRequest::from_validated_json(&scan).expect("scan request");
    assert_eq!(
        PatternScanRequest::from_validated_json(&scan).expect("scan request"),
        scan_request
    );
    assert_eq!(
        canonical_json(&scan_request),
        include_bytes!("../../../fixtures/golden/patterns/scan-request-valid.json")
    );
    let worker: serde_json::Value = serde_json::from_str(include_str!(
        "../../../fixtures/golden/patterns/worker-request-valid.json"
    ))
    .expect("worker golden");
    let worker_request =
        PatternWorkerRequest::from_validated_json(&worker).expect("worker request");
    assert_eq!(worker_request.rule_sources.len(), 1);
    assert_eq!(
        canonical_json(&worker_request),
        include_bytes!("../../../fixtures/golden/patterns/worker-request-valid.json")
    );
}

fn canonical_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize canonical JSON");
    bytes.push(b'\n');
    bytes
}
