// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Pipeline profiling: measures throughput of batch AEAD and MAC operations.

use kk_crypto::kk_mix::kk_mac;
use kk_crypto::{encode_aead_batch, EntropyPool};
use std::time::Instant;

fn main() {
    let secret = b"profile-bench-secret-2026";
    let pool = EntropyPool::new(2048).unwrap();
    // give pool time to fill
    std::thread::sleep(std::time::Duration::from_secs(2));

    let msg_size = 65536usize;
    let n = 1000;

    // 1) Pool draw time
    let t0 = Instant::now();
    let snaps: Vec<_> = (0..n).map(|_| pool.draw().unwrap()).collect();
    let pool_time = t0.elapsed();
    println!(
        "  Pool draw {n}x: {:?}  ({:.1} us/draw)",
        pool_time,
        pool_time.as_micros() as f64 / n as f64
    );

    // 2) Scalar MAC time - single-threaded baseline
    let key = [0x42u8; 32];
    let data = vec![0xABu8; msg_size];
    let t0 = Instant::now();
    for _ in 0..n {
        std::hint::black_box(kk_mac(&key, &data));
    }
    let scalar_mac = t0.elapsed();
    println!(
        "  Scalar MAC {n}x{msg_size}: {:?}  ({:.2} GiB/s single-thread)",
        scalar_mac,
        (n as f64 * msg_size as f64) / scalar_mac.as_secs_f64() / (1024.0 * 1024.0 * 1024.0)
    );

    // 3) Full pipeline (encode_aead_batch)
    let plaintext = vec![0xABu8; msg_size];
    let aad = b"bench-aad";
    let messages: Vec<(&[u8], &[u8])> = (0..n)
        .map(|_| (plaintext.as_slice(), aad.as_slice()))
        .collect();

    // Warmup
    let _ = encode_aead_batch(secret, &messages[..8], Some(&pool)).unwrap();

    let t0 = Instant::now();
    let _ = encode_aead_batch(secret, &messages, Some(&pool)).unwrap();
    let full_time = t0.elapsed();
    println!(
        "  Full pipeline {n}x{msg_size}: {:?}  ({:.2} GiB/s)",
        full_time,
        (n as f64 * msg_size as f64) / full_time.as_secs_f64() / (1024.0 * 1024.0 * 1024.0)
    );

    // Breakdown estimate
    let mac_pct = scalar_mac.as_secs_f64() / full_time.as_secs_f64() * 100.0;
    let pool_pct = pool_time.as_secs_f64() / full_time.as_secs_f64() * 100.0;
    println!("\n  --- Time budget vs pipeline ---");
    println!(
        "  Scalar MAC alone (1T): {:.1}% of pipeline wall-time",
        mac_pct
    );
    println!(
        "  Pool draws (serial):   {:.1}% of pipeline wall-time",
        pool_pct
    );
    println!("  → The rest is KDF/XOR + Rayon overhead + entropy fallback + alloc");

    let _ = snaps; // keep snaps alive
}
