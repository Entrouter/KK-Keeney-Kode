// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

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
