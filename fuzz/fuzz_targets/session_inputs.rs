#![no_main]

use sankaku_core::{SessionManifest, parse_psk_hex, validate_ticket_identity};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SessionManifest::from_bytes(data);

    if let Ok(as_text) = std::str::from_utf8(data) {
        let _ = parse_psk_hex(as_text);
    }

    let ticket_key = [0xAB; 32];
    let _ = validate_ticket_identity(&ticket_key, data, 0);
});
