// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

#![no_main]
use libfuzzer_sys::fuzz_target;
use kk_crypto::{EkaInitiator, EkaResponder};

fuzz_target!(|data: &[u8]| {
    // Use fuzzer data as a pre-shared key, needs at least 1 byte
    if data.is_empty() {
        return;
    }

    // Initiate
    let (initiator, msg1) = match EkaInitiator::new(data) {
        Ok(pair) => pair,
        Err(_) => return,
    };

    // Respond
    let (responder, msg2) = match EkaResponder::new(data, &msg1) {
        Ok(pair) => pair,
        Err(_) => return,
    };

    // Complete initiator side
    let (msg3, key_a) = match initiator.process_msg2(&msg2) {
        Ok(pair) => pair,
        Err(_) => return,
    };

    // Complete responder side
    let key_b = match responder.process_msg3(&msg3) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Both sides must derive same shared secret
    assert_eq!(key_a, key_b, "EKA key agreement must produce matching keys");
});
