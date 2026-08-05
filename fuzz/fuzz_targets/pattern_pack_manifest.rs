#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_patterns::{
    PatternPackManifest, PatternPackVerificationLimits, canonical_manifest_bytes,
};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1_048_576 {
        return;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        if let Ok(manifest) = serde_json::from_value::<PatternPackManifest>(value) {
            let _ = manifest.validate(&PatternPackVerificationLimits::default());
            let _ = canonical_manifest_bytes(&manifest);
        }
    }
});
