use pasol_patterns::{
    PATTERN_ENGINE, PATTERN_LIMITS_PROFILE, PATTERN_METADATA_POLICY, PATTERN_SCHEMA_VERSION,
    PatternInput, PatternLimits, PatternPackBundleInput, PatternPackIdentity, PatternPackManifest,
    PatternPackReference, PatternPackVerificationLimits, PatternReport, PatternScanRequest,
    PatternScanStatus, PatternSignatureState, PatternSourceManifest, PatternWorkerRequest,
    canonical_manifest_bytes, sign_pattern_pack, verify_signed_pattern_pack,
};
use proptest::prop_assert_eq;
use sha2::Digest;
use std::collections::BTreeMap;

fn signed_manifest_fixture() -> (
    PatternPackManifest,
    BTreeMap<String, Vec<u8>>,
    ed25519_dalek::SigningKey,
) {
    let source = b"rule marker { strings: $x = \"marker\" condition: $x }".to_vec();
    let mut sources = BTreeMap::new();
    sources.insert("rules/marker.yar".into(), source.clone());
    let manifest = PatternPackManifest {
        schema_version: PATTERN_SCHEMA_VERSION.into(),
        pack_id: "pasol.test.patterns".into(),
        pack_version: "1.0.0".into(),
        engine: PATTERN_ENGINE.into(),
        engine_version_requirement: "=1.19.0".into(),
        created_at: Some("2026-08-05T00:00:00Z".into()),
        limits_profile: Some(PATTERN_LIMITS_PROFILE.into()),
        metadata_policy: Some(PATTERN_METADATA_POLICY.into()),
        sources: vec![PatternSourceManifest {
            namespace: "pasol".into(),
            path: "rules/marker.yar".into(),
            sha256: hex::encode(sha2::Sha256::digest(source)),
        }],
    };
    (
        manifest,
        sources,
        ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
    )
}

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
        "pattern-pack-signature-1.0.0.schema.json",
        "trusted-key-store-1.0.0.schema.json",
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
            "pattern-pack-signature-1.0.0.schema.json" => {
                include_str!("../../../schemas/pattern-pack-signature-1.0.0.schema.json")
            }
            "trusted-key-store-1.0.0.schema.json" => {
                include_str!("../../../schemas/trusted-key-store-1.0.0.schema.json")
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

#[test]
fn pattern_manifest_signing_is_deterministic_and_verifies_bounded_sources() {
    let (manifest, sources, signing_key) = signed_manifest_fixture();
    let limits = PatternPackVerificationLimits::default();
    let signature = sign_pattern_pack(&manifest, &sources, "test-key", &signing_key, &limits)
        .expect("sign manifest");
    let mut store = pasol_trust::TrustedKeyStore::empty();
    store
        .add(pasol_trust::TrustedKey {
            key_id: "test-key".into(),
            algorithm: "ed25519".into(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            status: pasol_trust::KeyStatus::Active,
            trusted_from: "2026-08-05T00:00:00Z".into(),
            revoked_at: None,
            replacement_key_id: None,
        })
        .expect("trust key");
    let bundle = PatternPackBundleInput {
        manifest_json: serde_json::to_vec(&manifest).expect("manifest json"),
        signature_json: Some(serde_json::to_vec(&signature).expect("signature json")),
        sources,
    };
    let verified =
        verify_signed_pattern_pack(&bundle, &store, &semver::Version::new(1, 19, 0), &limits)
            .expect("verify pack");
    assert_eq!(
        verified.identity().signature_state,
        PatternSignatureState::Verified
    );
}

#[test]
fn source_mutation_and_revocation_fail_verification() {
    let (manifest, mut sources, signing_key) = signed_manifest_fixture();
    let limits = PatternPackVerificationLimits::default();
    let signature =
        sign_pattern_pack(&manifest, &sources, "test-key", &signing_key, &limits).expect("sign");
    sources.get_mut("rules/marker.yar").expect("source")[0] ^= 1;
    let mut store = pasol_trust::TrustedKeyStore::empty();
    store
        .add(pasol_trust::TrustedKey {
            key_id: "test-key".into(),
            algorithm: "ed25519".into(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            status: pasol_trust::KeyStatus::Active,
            trusted_from: "2026-08-05T00:00:00Z".into(),
            revoked_at: None,
            replacement_key_id: None,
        })
        .expect("trust");
    let bundle = PatternPackBundleInput {
        manifest_json: serde_json::to_vec(&manifest).expect("manifest"),
        signature_json: Some(serde_json::to_vec(&signature).expect("signature")),
        sources,
    };
    assert!(
        verify_signed_pattern_pack(&bundle, &store, &semver::Version::new(1, 19, 0), &limits)
            .is_err()
    );
    store
        .revoke("test-key", "2026-08-05T01:00:00Z".into())
        .expect("revoke");
    let (manifest, sources, _) = signed_manifest_fixture();
    let signature =
        sign_pattern_pack(&manifest, &sources, "test-key", &signing_key, &limits).expect("sign");
    let bundle = PatternPackBundleInput {
        manifest_json: serde_json::to_vec(&manifest).expect("manifest"),
        signature_json: Some(serde_json::to_vec(&signature).expect("signature")),
        sources,
    };
    assert!(
        verify_signed_pattern_pack(&bundle, &store, &semver::Version::new(1, 19, 0), &limits)
            .is_err()
    );
}

#[test]
fn manifest_mutations_are_rejected_before_verification() {
    let (mut manifest, sources, signing_key) = signed_manifest_fixture();
    let limits = PatternPackVerificationLimits::default();
    for mutation in [
        |m: &mut PatternPackManifest| m.engine = "unknown".into(),
        |m: &mut PatternPackManifest| m.pack_version = "not-semver".into(),
        |m: &mut PatternPackManifest| m.sources[0].path = "../escape.yar".into(),
        |m: &mut PatternPackManifest| m.sources[0].sha256 = "A".repeat(64),
    ] {
        let mut mutated = manifest.clone();
        mutation(&mut mutated);
        assert!(mutated.validate(&limits).is_err());
    }
    manifest.sources.push(manifest.sources[0].clone());
    assert!(sign_pattern_pack(&manifest, &sources, "test-key", &signing_key, &limits).is_err());
}

proptest::proptest! {
    #[test]
fn canonicalization_is_independent_of_source_order(seed in 0u8..=255) {
        let mut first = signed_manifest_fixture().0;
        let mut second = first.clone();
        first.sources.push(PatternSourceManifest { namespace: "z".into(), path: format!("rules/{seed}.yar"), sha256: "b".repeat(64) });
        second.sources.insert(0, PatternSourceManifest { namespace: "z".into(), path: format!("rules/{seed}.yar"), sha256: "b".repeat(64) });
        prop_assert_eq!(
            canonical_manifest_bytes(&first).expect("canonical first"),
            canonical_manifest_bytes(&second).expect("canonical second")
        );
    }
}

#[test]
fn checked_in_signed_and_development_fixtures_verify_with_fixed_identity() {
    let manifest_json =
        include_bytes!("../../../fixtures/pattern-packs/signed-valid/manifest.json").to_vec();
    let signature_json =
        include_bytes!("../../../fixtures/pattern-packs/signed-valid/manifest.sig.json").to_vec();
    let source =
        include_bytes!("../../../fixtures/pattern-packs/signed-valid/rules/marker.yar").to_vec();
    let mut sources = BTreeMap::new();
    sources.insert("marker.yar".into(), source);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let mut store = pasol_trust::TrustedKeyStore::empty();
    store
        .add(pasol_trust::TrustedKey {
            key_id: "test-key".into(),
            algorithm: "ed25519".into(),
            public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            status: pasol_trust::KeyStatus::Active,
            trusted_from: "2026-08-05T00:00:00Z".into(),
            revoked_at: None,
            replacement_key_id: None,
        })
        .expect("trust fixture key");
    let verified = verify_signed_pattern_pack(
        &PatternPackBundleInput {
            manifest_json,
            signature_json: Some(signature_json),
            sources,
        },
        &store,
        &semver::Version::new(1, 19, 0),
        &PatternPackVerificationLimits::default(),
    )
    .expect("fixture verifies");
    assert_eq!(verified.signing_key_id(), Some("test-key"));
    assert_eq!(verified.sources().len(), 1);
    let development = PatternPackBundleInput {
        manifest_json: include_bytes!(
            "../../../fixtures/pattern-packs/development-valid/manifest.json"
        )
        .to_vec(),
        signature_json: None,
        sources: [(
            "marker.yar".into(),
            include_bytes!("../../../fixtures/pattern-packs/development-valid/rules/marker.yar")
                .to_vec(),
        )]
        .into_iter()
        .collect(),
    };
    assert!(
        verify_signed_pattern_pack(
            &development,
            &store,
            &semver::Version::new(1, 19, 0),
            &PatternPackVerificationLimits::default()
        )
        .is_err()
    );
}

fn canonical_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize canonical JSON");
    bytes.push(b'\n');
    bytes
}
