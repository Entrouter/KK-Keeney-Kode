// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

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
