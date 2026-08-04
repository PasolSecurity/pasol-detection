#![allow(clippy::unwrap_used)]

use pasol_reputation::{
    CacheKey, CachePolicy, FixedClock, LocalReputationProvider, LocalStore, ReputationCache,
    ReputationContext, ReputationEntry, ReputationProvider, ReputationState, Sha256, report_at,
    validate_cache_json, validate_cli_error_json, validate_report_json,
};
use serde_json::Value;
use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn golden(path: &str, value: &Value) {
    let actual = serde_json::to_string(value).unwrap();
    let target = root().join(path);
    if std::env::var_os("PASOL_UPDATE_GOLDENS").is_some() {
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, format!("{actual}\n")).unwrap();
    }
    let expected = fs::read_to_string(&target).unwrap();
    assert_eq!(expected, format!("{actual}\n"), "golden mismatch: {path}");
}

fn entry(hash: &str, state: ReputationState, expires_at: Option<&str>) -> ReputationEntry {
    ReputationEntry {
        sha256: hash.into(),
        state,
        reason: Some("deterministic fixture".into()),
        source: Some("fixture".into()),
        labels: vec!["test".into()],
        created_at: "2025-12-31T00:00:00Z".into(),
        expires_at: expires_at.map(str::to_owned),
        enabled: true,
    }
}

fn report_for(store: LocalStore, hash: &str, clock: &FixedClock) -> Value {
    let provider = LocalReputationProvider::new(store);
    let typed = Sha256::parse(hash).unwrap();
    let result = provider
        .lookup_hash(
            &typed,
            &ReputationContext {
                clock,
                query_type: "sha256",
            },
        )
        .unwrap();
    serde_json::to_value(report_at(hash, result, "2026-01-01T00:00:00Z").unwrap()).unwrap()
}

#[test]
fn reputation_reports_are_schema_valid_and_byte_stable() {
    let clock = FixedClock("2026-01-01T00:00:00Z".into());
    let benign = "a".repeat(64);
    let malicious = "b".repeat(64);
    let suspicious = "c".repeat(64);
    let expired = "d".repeat(64);
    for (name, store, hash) in [
        (
            "known-benign.json",
            LocalStore {
                schema_version: "1.0.0".into(),
                entries: vec![entry(&benign, ReputationState::KnownBenign, None)],
            },
            benign.as_str(),
        ),
        (
            "known-malicious.json",
            LocalStore {
                schema_version: "1.0.0".into(),
                entries: vec![entry(&malicious, ReputationState::KnownMalicious, None)],
            },
            malicious.as_str(),
        ),
        (
            "suspicious.json",
            LocalStore {
                schema_version: "1.0.0".into(),
                entries: vec![
                    entry(&suspicious, ReputationState::KnownBenign, None),
                    entry(&suspicious, ReputationState::KnownMalicious, None),
                ],
            },
            suspicious.as_str(),
        ),
        (
            "unknown.json",
            LocalStore {
                schema_version: "1.0.0".into(),
                entries: Vec::new(),
            },
            "e000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "expired-as-unknown.json",
            LocalStore {
                schema_version: "1.0.0".into(),
                entries: vec![entry(
                    &expired,
                    ReputationState::KnownMalicious,
                    Some("2025-12-31T23:59:59Z"),
                )],
            },
            expired.as_str(),
        ),
    ] {
        let value = report_for(store, hash, &clock);
        validate_report_json(&value).unwrap();
        golden(&format!("fixtures/golden/reputation/{name}"), &value);
    }
}

#[test]
fn cache_hit_and_miss_reports_are_schema_valid_and_byte_stable() {
    let clock = FixedClock("2026-01-01T00:00:00Z".into());
    let hash = "f".repeat(64);
    let store = LocalStore {
        schema_version: "1.0.0".into(),
        entries: vec![entry(&hash, ReputationState::KnownBenign, None)],
    };
    let provider = LocalReputationProvider::new(store.clone());
    let typed = Sha256::parse(&hash).unwrap();
    let context = ReputationContext {
        clock: &clock,
        query_type: "sha256",
    };
    let fresh = provider.lookup_hash(&typed, &context).unwrap();
    let mut cache = ReputationCache::empty();
    let key = CacheKey {
        provider: "local-pasol-reputation".into(),
        provider_version: "0.1.0".into(),
        query_type: "sha256".into(),
        sha256: hash.clone(),
    };
    let revision = store.revision().unwrap();
    cache
        .put(
            key.clone(),
            revision.clone(),
            fresh.clone(),
            &clock,
            CachePolicy::default(),
        )
        .unwrap();
    let miss =
        serde_json::to_value(report_at(&hash, fresh, "2026-01-01T00:00:00Z").unwrap()).unwrap();
    validate_report_json(&miss).unwrap();
    golden("fixtures/golden/reputation/cache-miss.json", &miss);
    let hit = cache.get(&key, &revision, &clock).unwrap().unwrap();
    let hit = serde_json::to_value(report_at(&hash, hit, "2026-01-01T00:00:00Z").unwrap()).unwrap();
    validate_report_json(&hit).unwrap();
    golden("fixtures/golden/reputation/cache-hit.json", &hit);
}

#[test]
fn cli_error_goldens_are_schema_valid_and_byte_stable() {
    let errors = [
        (
            "invalid-hash.json",
            "reputation.hash.invalid",
            "invalid_input",
            "The SHA-256 hash is invalid",
        ),
        (
            "corrupt-store.json",
            "reputation.store.invalid",
            "invalid_input",
            "The reputation store or cache is invalid",
        ),
        (
            "corrupt-cache.json",
            "reputation.store.invalid",
            "invalid_input",
            "The reputation store or cache is invalid",
        ),
        (
            "missing-store.json",
            "reputation.io.failure",
            "io",
            "The reputation file could not be read or written",
        ),
        (
            "resource-limit.json",
            "reputation.resource.limit",
            "resource_limit",
            "The reputation resource limit was exceeded",
        ),
    ];
    for (name, code, class, message) in errors {
        let value = serde_json::json!({
            "schema_version": "1.0.0",
            "error": {"code": code, "class": class, "message": message}
        });
        validate_cli_error_json(&value).unwrap();
        golden(&format!("fixtures/golden/reputation/{name}"), &value);
    }
}

#[test]
fn cache_schema_is_valid_for_generated_document() {
    let value = serde_json::to_value(ReputationCache::empty()).unwrap();
    validate_cache_json(&value).unwrap();
}
