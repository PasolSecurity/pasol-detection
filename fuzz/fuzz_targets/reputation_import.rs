#![no_main]
use libfuzzer_sys::fuzz_target;
use pasol_reputation::{LocalStore, validate_store_json};
use serde_json::Value;

const MAX_INPUT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT)];
    if let Ok(value) = serde_json::from_slice::<Value>(data) {
        if validate_store_json(&value).is_ok() {
            let _ = serde_json::from_value::<LocalStore>(value);
        }
    }
});
