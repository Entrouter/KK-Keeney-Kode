// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::kk_mix::{kk_hash, KkSponge};

fuzz_target!(|data: &[u8]| {
    // Fuzz the convenience wrapper
    let _digest = kk_hash(data);

    // Fuzz incremental absorb+squeeze with various split points
    if data.len() >= 2 {
        let split = data[0] as usize % data.len().max(1);
        let mut sponge = KkSponge::new();
        sponge.absorb(&data[..split]);
        sponge.absorb(&data[split..]);
        let _out = sponge.squeeze(32);
    }
});
