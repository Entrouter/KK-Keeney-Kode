// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::kk_mix::kk_kdf;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    // Carve the input into key, salt, info using first two bytes as split points
    let s1 = (data[0] as usize) % data.len();
    let s2 = s1 + (data[1] as usize) % (data.len() - s1).max(1);
    let s2 = s2.min(data.len());

    let key = &data[..s1];
    let salt = &data[s1..s2];
    let info = &data[s2..];

    // Derive between 1 and 256 bytes
    let out_len = ((data[0] as usize) % 256) + 1;
    let _derived = kk_kdf(key, salt, info, out_len);
});
