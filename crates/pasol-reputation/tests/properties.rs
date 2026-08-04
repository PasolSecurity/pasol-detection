#![allow(clippy::unwrap_used)]

use pasol_reputation::{
    CacheKey, CachePolicy, FixedClock, LocalReputationProvider, LocalStore, ReputationCache,
    ReputationContext, ReputationEntry, ReputationProvider, ReputationState, Sha256,
};
use proptest::prelude::*;

fn hash(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn entry(sha256: String, state: ReputationState) -> ReputationEntry {
    ReputationEntry {
        sha256,
        state,
        reason: Some("property".into()),
        source: Some("property".into()),
        labels: Vec::new(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: None,
        enabled: true,
    }
}

proptest! {
    #[test]
    fn valid_sha256_parse_and_format_round_trip(bytes in prop::array::uniform32(any::<u8>())) {
        let value = hash(&bytes);
        let parsed = Sha256::parse(&value).unwrap();
        prop_assert_eq!(parsed.as_str(), value);
    }

    #[test]
    fn cache_keys_are_unique_when_hash_changes(
        first in prop::array::uniform32(any::<u8>()),
        second in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(first != second);
        let base = CacheKey {
            provider: "local-pasol-reputation".into(),
            provider_version: "0.1.0".into(),
            query_type: "sha256".into(),
            sha256: hash(&first),
        };
        let mut changed = base.clone();
        changed.sha256 = hash(&second);
        prop_assert_ne!(base, changed);
    }

    #[test]
    fn store_serialization_preserves_semantic_records(
        bytes in prop::array::uniform32(any::<u8>()),
        malicious in any::<bool>(),
    ) {
        let state = if malicious { ReputationState::KnownMalicious } else { ReputationState::KnownBenign };
        let store = LocalStore {
            schema_version: "1.0.0".into(),
            entries: vec![entry(hash(&bytes), state)],
        };
        let encoded = serde_json::to_value(&store).unwrap();
        let decoded: LocalStore = serde_json::from_value(encoded).unwrap();
        prop_assert_eq!(store, decoded);
    }
}

#[test]
fn ordering_does_not_change_lookup_and_conflicts_are_not_benign() {
    let first = "a".repeat(64);
    let second = "b".repeat(64);
    let normal = LocalStore {
        schema_version: "1.0.0".into(),
        entries: vec![
            entry(first.clone(), ReputationState::KnownBenign),
            entry(second.clone(), ReputationState::KnownMalicious),
        ],
    };
    let reversed = LocalStore {
        schema_version: "1.0.0".into(),
        entries: normal.entries.iter().cloned().rev().collect(),
    };
    assert_eq!(
        normal.lookup(&first).unwrap(),
        reversed.lookup(&first).unwrap()
    );
    let conflict = LocalStore {
        schema_version: "1.0.0".into(),
        entries: vec![
            entry(first.clone(), ReputationState::KnownBenign),
            entry(first.clone(), ReputationState::KnownMalicious),
        ],
    };
    assert_eq!(
        conflict.lookup(&first).unwrap().state,
        ReputationState::Suspicious
    );
}

#[test]
fn source_revision_change_invalidates_cache_and_expiry_is_not_a_hit() {
    let clock = FixedClock("2026-01-01T00:00:00Z".into());
    let hash = "c".repeat(64);
    let store = LocalStore {
        schema_version: "1.0.0".into(),
        entries: vec![entry(hash.clone(), ReputationState::KnownBenign)],
    };
    let provider = LocalReputationProvider::new(store.clone());
    let typed = Sha256::parse(&hash).unwrap();
    let context = ReputationContext {
        clock: &clock,
        query_type: "sha256",
    };
    let result = provider.lookup_hash(&typed, &context).unwrap();
    let key = CacheKey {
        provider: "local-pasol-reputation".into(),
        provider_version: "0.1.0".into(),
        query_type: "sha256".into(),
        sha256: hash,
    };
    let revision = store.revision().unwrap();
    let mut cache = ReputationCache::empty();
    cache
        .put(
            key.clone(),
            revision.clone(),
            result,
            &clock,
            CachePolicy {
                benign_seconds: 0,
                ..CachePolicy::default()
            },
        )
        .unwrap();
    assert!(cache.get(&key, &revision, &clock).unwrap().is_none());
    cache
        .put(
            key.clone(),
            revision.clone(),
            provider.lookup_hash(&typed, &context).unwrap(),
            &clock,
            CachePolicy::default(),
        )
        .unwrap();
    assert!(cache.get(&key, &"0".repeat(64), &clock).unwrap().is_none());
    assert!(cache.get(&key, &revision, &clock).unwrap().is_some());
}
