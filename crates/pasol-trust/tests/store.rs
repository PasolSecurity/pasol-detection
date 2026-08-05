use ed25519_dalek::SigningKey;
use pasol_trust::{KeyStatus, TrustError, TrustedKey, TrustedKeyStore};

fn key() -> TrustedKey {
    let signing = SigningKey::from_bytes(&[7; 32]);
    TrustedKey {
        key_id: "test-key".into(),
        algorithm: "ed25519".into(),
        public_key_hex: signing
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        status: KeyStatus::Active,
        trusted_from: "2026-08-05T00:00:00Z".into(),
        revoked_at: None,
        replacement_key_id: None,
    }
}

#[test]
fn active_and_retired_keys_resolve_but_revoked_keys_do_not() {
    let mut store = TrustedKeyStore::empty();
    store.add(key()).expect("add key");
    assert!(store.resolve_for_verification("test-key").is_ok());
    store.keys[0].status = KeyStatus::Retired;
    assert!(store.resolve_for_verification("test-key").is_ok());
    store
        .revoke("test-key", "2026-08-05T01:00:00Z".into())
        .expect("revoke");
    assert!(matches!(
        store.resolve_for_verification("test-key"),
        Err(TrustError::RevokedKey(_))
    ));
}

#[test]
fn duplicate_unknown_and_invalid_keys_are_rejected() {
    let mut store = TrustedKeyStore::empty();
    store.add(key()).expect("add key");
    assert!(store.add(key()).is_err());
    assert!(matches!(
        store.resolve_for_verification("missing"),
        Err(TrustError::UnknownKey(_))
    ));
    store.keys[0].public_key_hex = "zz".into();
    assert!(store.validate().is_err());
}

#[test]
fn store_round_trip_and_atomic_persistence_are_schema_stable() {
    let mut store = TrustedKeyStore::empty();
    store.add(key()).expect("add key");
    let root = std::env::temp_dir().join(format!("pasol-trust-{}", std::process::id()));
    let path = root.join("keys.json");
    store.save_atomic(&path).expect("save");
    let loaded = TrustedKeyStore::load(&path).expect("load");
    assert_eq!(loaded, store);
    let _ = std::fs::remove_dir_all(root);
}
