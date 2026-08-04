#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_reputation::{FixedClock, LocalStore, ReputationEntry, ReputationState};

fn hash(byte: u8) -> String {
    std::iter::repeat_n(byte, 64).map(char::from).collect()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let sha = hash(b'a');
    let state = |value: u8| {
        if value & 1 == 0 {
            ReputationState::KnownBenign
        } else {
            ReputationState::KnownMalicious
        }
    };
    let make = |value: u8| ReputationEntry {
        sha256: sha.clone(),
        state: state(value),
        reason: None,
        source: None,
        labels: Vec::new(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: None,
        enabled: true,
    };
    let first = LocalStore {
        schema_version: "1.0.0".into(),
        entries: vec![make(data[0]), make(data[1])],
    };
    let second = LocalStore {
        schema_version: "1.0.0".into(),
        entries: first.entries.iter().cloned().rev().collect(),
    };
    let clock = FixedClock("2026-01-01T00:00:00Z".into());
    let left = first.lookup_at(&sha, &clock).unwrap();
    let right = second.lookup_at(&sha, &clock).unwrap();
    assert_eq!(left, right);
    if data[0] & 1 != data[1] & 1 {
        assert_eq!(left.state, ReputationState::Suspicious);
    }
});
