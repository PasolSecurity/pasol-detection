#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_reputation::{FixedClock, LocalStore, ReputationEntry, ReputationState};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let expiry = if data[0] & 1 == 0 {
        Some("2025-12-31T23:59:59Z".into())
    } else {
        None
    };
    let entry = ReputationEntry {
        sha256: "b".repeat(64),
        state: ReputationState::KnownMalicious,
        reason: None,
        source: None,
        labels: Vec::new(),
        created_at: "2025-12-31T00:00:00Z".into(),
        expires_at: expiry,
        enabled: true,
    };
    let store = LocalStore {
        schema_version: "1.0.0".into(),
        entries: vec![entry],
    };
    let result = store
        .lookup_at(
            "b".repeat(64).as_str(),
            &FixedClock("2026-01-01T00:00:00Z".into()),
        )
        .unwrap();
    if data[0] & 1 == 0 {
        assert_eq!(result.state, ReputationState::Unknown);
    }
});
