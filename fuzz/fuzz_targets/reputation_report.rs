#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_reputation::validate_report_json;
use serde_json::Value;

const MAX_INPUT: usize = 1 << 20;
const MAX_OUTPUT: usize = 4 << 20;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        let _ = validate_report_json(&value);
        if let Ok(encoded) = serde_json::to_vec(&value) {
            assert!(encoded.len() <= MAX_OUTPUT);
        }
    }
});
