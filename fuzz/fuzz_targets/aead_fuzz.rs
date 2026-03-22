// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::{encode_aead, decode_aead};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Split: [secret_len_byte | aad_len_byte | secret | aad | plaintext]
    let secret_len = ((data[0] as usize) % 63).max(1).min(data.len() - 2);
    let remaining = &data[2..];
    if remaining.len() < secret_len + 1 {
        return;
    }
    let aad_len = ((data[1] as usize) % 64).min(remaining.len() - secret_len);
    let secret = &remaining[..secret_len];
    let aad = &remaining[secret_len..secret_len + aad_len];
    let plaintext = &remaining[secret_len + aad_len..];

    if plaintext.is_empty() {
        return;
    }

    let packet = match encode_aead(secret, plaintext, aad) {
        Ok(p) => p,
        Err(_) => return,
    };

    let recovered = decode_aead(secret, &packet).expect("decode_aead must succeed");
    assert_eq!(recovered, plaintext);
});
