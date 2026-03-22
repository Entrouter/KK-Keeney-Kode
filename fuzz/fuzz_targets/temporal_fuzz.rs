// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use kk_crypto::{encode_bound, decode_bound, generate_challenge, GENESIS_MAC};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let secret_len = ((data[0] as usize) % 63).max(1).min(data.len() - 1);
    let secret = &data[1..1 + secret_len];
    let plaintext = &data[1 + secret_len..];

    if plaintext.is_empty() {
        return;
    }

    let nonce = match generate_challenge() {
        Ok(n) => n,
        Err(_) => return,
    };

    let packet = match encode_bound(secret, plaintext, &nonce, &GENESIS_MAC) {
        Ok(p) => p,
        Err(_) => return,
    };

    let recovered = decode_bound(secret, &packet, &nonce, Duration::from_secs(60))
        .expect("decode_bound must succeed for fresh valid packet");
    assert_eq!(recovered, plaintext);
});
