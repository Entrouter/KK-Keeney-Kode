#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::{encode, decode};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // First byte selects a secret length, rest is plaintext
    let secret_len = ((data[0] as usize) % data.len().saturating_sub(1)).max(1);
    let secret = &data[1..1 + secret_len];
    let plaintext = &data[1 + secret_len..];

    if secret.is_empty() || plaintext.is_empty() {
        return;
    }

    // Encode should succeed
    let packet = match encode(secret, plaintext) {
        Ok(p) => p,
        Err(_) => return,
    };

    // Decode with the same secret must recover plaintext
    let recovered = decode(secret, &packet).expect("decode must succeed for valid packet");
    assert_eq!(recovered, plaintext);
});
