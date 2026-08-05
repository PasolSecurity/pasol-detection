#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_patterns::{PatternPackSignature, validate_signature_json};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }
    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        let _ = validate_signature_json(&value);
        let _ = serde_json::from_value::<PatternPackSignature>(value);
    }
});
