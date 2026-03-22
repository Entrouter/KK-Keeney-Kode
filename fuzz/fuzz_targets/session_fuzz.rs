// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::{encode_session, decode_session, RopeRatchet};

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    // Split: [num_msgs | secret ... | plaintext_pool ...]
    let num_msgs = ((data[0] as usize) % 4).max(1);
    let secret_len = ((data[1] as usize) % 32).max(1).min(data.len() - 2);
    let secret = &data[2..2 + secret_len];
    let pool = &data[2 + secret_len..];

    if pool.is_empty() {
        return;
    }

    let context = b"fuzz-session";
    let mut sender = match RopeRatchet::new(secret, context) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut receiver = match RopeRatchet::new(secret, context) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Send num_msgs messages, splitting the pool evenly
    let chunk_size = (pool.len() / num_msgs).max(1);
    for i in 0..num_msgs {
        let start = i * chunk_size;
        let end = ((i + 1) * chunk_size).min(pool.len());
        if start >= pool.len() {
            break;
        }
        let plaintext = &pool[start..end];
        if plaintext.is_empty() {
            continue;
        }

        let packet = match encode_session(&mut sender, plaintext) {
            Ok(p) => p,
            Err(_) => return,
        };
        let recovered = decode_session(&mut receiver, &packet)
            .expect("decode_session must succeed for valid packet");
        assert_eq!(recovered, plaintext);
    }
});
