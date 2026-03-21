// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

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
