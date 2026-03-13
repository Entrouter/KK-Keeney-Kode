#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::kk_mix::{kk_mac, kk_mac_verify};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Split into key and message
    let split = (data[0] as usize) % data.len();
    let key = &data[..split];
    let message = &data[split..];

    // Compute MAC and verify it passes
    let tag = kk_mac(key, message);
    assert!(kk_mac_verify(key, message, &tag));

    // Flip a bit in the tag and confirm verification fails
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(!kk_mac_verify(key, message, &bad_tag));
});
