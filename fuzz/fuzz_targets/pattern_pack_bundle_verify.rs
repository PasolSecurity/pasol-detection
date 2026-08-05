#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_patterns::{
    PatternPackBundleInput, PatternPackVerificationLimits, verify_signed_pattern_pack,
};
use pasol_trust::TrustedKeyStore;
use semver::Version;
use std::collections::BTreeMap;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    let bundle = PatternPackBundleInput {
        manifest_json: data.to_vec(),
        signature_json: None,
        sources: BTreeMap::new(),
    };
    let _ = verify_signed_pattern_pack(
        &bundle,
        &TrustedKeyStore::empty(),
        &Version::new(1, 19, 0),
        &PatternPackVerificationLimits::default(),
    );
});
