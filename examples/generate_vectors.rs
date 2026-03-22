// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Generate deterministic test vectors for all KK primitives.
//!
//! Run: `cargo run --example generate_vectors`
//!
//! The output is hex-encoded and used to populate `tests/vectors.rs`
//! and `KK_TEST_VECTORS.md`.

use kk_crypto::entropy::EntropySnapshot;
use kk_crypto::kk_mix::{
    kk_hash, kk_kdf, kk_mac, kk_mac_with_entropy, kk_permute,
    kk_permute_with_schedule, rotations_from_entropy, KkState,
};
use kk_crypto::{encode_with_snapshot, encode_aead_with_snapshot, decode, decode_aead};
use kk_crypto::session::RopeRatchet;

/// Build a canonical test snapshot from an index (0–4).
fn make_snapshot(index: u8) -> EntropySnapshot {
    let mut bytes = [0u8; 32];
    // Fill with a recognisable pattern: index repeated, then ascending
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = index.wrapping_add(i as u8);
    }
    let timestamp_nanos: u128 = 1_000_000_000_000 + (index as u128) * 111_111_111;
    EntropySnapshot {
        bytes,
        timestamp_nanos,
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_state(state: &KkState) -> String {
    state
        .iter()
        .map(|w| format!("{:016x}", w))
        .collect::<Vec<_>>()
        .join("")
}

fn main() {
    println!("═══════════════════════════════════════════════════════════");
    println!("  KK DETERMINISTIC TEST VECTORS");
    println!("═══════════════════════════════════════════════════════════\n");

    // ── Snapshots ──
    println!("## Canonical Snapshots\n");
    for i in 0..5u8 {
        let s = make_snapshot(i);
        println!("SNAPSHOT_{}: bytes={} timestamp_nanos={}", i, hex(&s.bytes), s.timestamp_nanos);
    }
    println!();

    // ── kk_hash ──
    println!("## kk_hash\n");
    let hash_inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one_byte_0x42", vec![0x42]),
        ("abc", b"abc".to_vec()),
        ("32_zeros", vec![0u8; 32]),
        ("64_ascending", (0..64u8).collect()),
        ("128_0xff", vec![0xFFu8; 128]),
        ("1024_pattern", (0..=255u8).cycle().take(1024).collect()),
        ("all_zero_64", vec![0u8; 64]),
        ("all_0xff_32", vec![0xFFu8; 32]),
        ("utf8_hello", "Hello, 世界! 🌍".as_bytes().to_vec()),
    ];
    for (label, input) in &hash_inputs {
        let digest = kk_hash(input);
        println!("kk_hash({}) = {}", label, hex(&digest));
    }
    println!();

    // ── kk_kdf ──
    println!("## kk_kdf\n");
    let kdf_cases: Vec<(&str, &[u8], &[u8], &[u8], usize)> = vec![
        ("basic_32", b"secret-key", b"salt-value", b"info-string", 32),
        ("basic_64", b"secret-key", b"salt-value", b"info-string", 64),
        ("empty_salt", b"key", b"", b"info", 32),
        ("empty_info", b"key", b"salt", b"", 32),
        ("long_key", &[0xABu8; 128], b"salt", b"info", 32),
        ("long_salt", b"key", &[0xCDu8; 128], b"info", 32),
        ("16_bytes", b"key", b"salt", b"short", 16),
        ("128_bytes", b"key", b"salt", b"long-output", 128),
    ];
    for (label, key, salt, info, len) in &kdf_cases {
        let out = kk_kdf(key, salt, info, *len);
        println!("kk_kdf({}) = {}", label, hex(&out));
    }
    println!();

    // ── kk_mac ──
    println!("## kk_mac\n");
    let mac_cases: Vec<(&str, &[u8], &[u8])> = vec![
        ("basic", b"mac-key", b"message-to-authenticate"),
        ("empty_msg", b"mac-key", b""),
        ("long_msg", b"mac-key", &[0x55u8; 256]),
        ("long_key", &[0xAAu8; 64], b"short message"),
        ("single_byte", b"k", b"m"),
        ("binary", &[0x00, 0xFF, 0x80], &[0x01, 0x02, 0x03, 0x04]),
    ];
    for (label, key, message) in &mac_cases {
        let tag = kk_mac(key, message);
        println!("kk_mac({}) = {}", label, hex(&tag));
    }
    println!();

    // ── kk_mac_with_entropy ──
    println!("## kk_mac_with_entropy\n");
    let snap0 = make_snapshot(0);
    let snap1_ent = make_snapshot(1);
    let long_msg_ent = vec![0x55u8; 256];
    let mac_ent_cases: Vec<(&str, &[u8], &[u8], &[u8])> = vec![
        ("ent_basic", b"mac-key", b"message", &snap0.bytes),
        ("ent_long", b"mac-key", &long_msg_ent, &snap0.bytes),
        ("ent_snap1", b"mac-key", b"message", &snap1_ent.bytes),
    ];
    for (label, key, message, entropy) in &mac_ent_cases {
        let tag = kk_mac_with_entropy(key, message, entropy);
        println!("kk_mac_with_entropy({}) = {}", label, hex(&tag));
    }
    println!();

    // ── kk_permute ──
    println!("## kk_permute\n");

    // Default rotations  - start from all-zero state
    let mut state_zero: KkState = [0u64; 25];
    println!("permute_zero_in  = {}", hex_state(&state_zero));
    kk_permute(&mut state_zero);
    println!("permute_zero_out = {}", hex_state(&state_zero));

    // Default rotations  - start from ascending state
    let mut state_asc: KkState = core::array::from_fn(|i| i as u64);
    println!("permute_asc_in   = {}", hex_state(&state_asc));
    kk_permute(&mut state_asc);
    println!("permute_asc_out  = {}", hex_state(&state_asc));

    // Custom rotations from snapshot 0
    let custom_rots = rotations_from_entropy(&make_snapshot(0).bytes);
    let mut state_custom1: KkState = [0u64; 25];
    println!("permute_custom0_in  = {}", hex_state(&state_custom1));
    kk_permute_with_schedule(&mut state_custom1, &custom_rots);
    println!("permute_custom0_out = {}", hex_state(&state_custom1));

    // Custom rotations from snapshot 2
    let custom_rots2 = rotations_from_entropy(&make_snapshot(2).bytes);
    let mut state_custom2: KkState = [0u64; 25];
    println!("permute_custom2_in  = {}", hex_state(&state_custom2));
    kk_permute_with_schedule(&mut state_custom2, &custom_rots2);
    println!("permute_custom2_out = {}", hex_state(&state_custom2));
    println!();

    // ── rotations_from_entropy ──
    println!("## rotations_from_entropy\n");
    for i in [0u8, 1, 2] {
        let snap = make_snapshot(i);
        let rots = rotations_from_entropy(&snap.bytes);
        let flat: Vec<String> = rots.iter().map(|[a, b]| format!("[{},{}]", a, b)).collect();
        println!("rotations_from_entropy(snap_{}) = [{}]", i, flat.join(", "));
    }
    println!();

    // ── encode/decode with fixed snapshot ──
    println!("## encode_with_snapshot\n");
    let enc_cases: Vec<(&str, &[u8], &[u8], u8)> = vec![
        ("hello", b"shared-secret", b"Hello, KK!", 0),
        ("binary", b"key-two", &[0x00, 0xFF, 0x80, 0x7F], 1),
        ("long", b"key-three", b"The quick brown fox jumps over the lazy dog", 2),
        ("single", b"k", b"X", 3),
    ];
    for (label, secret, plaintext, snap_idx) in &enc_cases {
        let snap = make_snapshot(*snap_idx);
        let packet = encode_with_snapshot(secret, plaintext, snap.clone()).unwrap();
        println!("encode({}):", label);
        println!("  ciphertext = {}", hex(&packet.ciphertext));
        println!("  commitment = {}", hex(&packet.commitment.mac));
        // Verify roundtrip
        let recovered = decode(secret, &packet).unwrap();
        assert_eq!(&recovered, plaintext, "roundtrip failed for {}", label);
        println!("  roundtrip   = OK");
    }
    println!();

    // ── encode_aead with fixed snapshot ──
    println!("## encode_aead_with_snapshot\n");
    let aead_cases: Vec<(&str, &[u8], &[u8], &[u8], u8)> = vec![
        ("basic_aead", b"shared-secret", b"Hello AEAD!", b"header-v1", 0),
        ("empty_aad", b"key-two", b"payload", b"", 1),
        ("long_aad", b"key-three", b"msg", &[0xAA; 64], 2),
    ];
    for (label, secret, plaintext, aad, snap_idx) in &aead_cases {
        let snap = make_snapshot(*snap_idx);
        let packet = encode_aead_with_snapshot(secret, plaintext, aad, snap.clone()).unwrap();
        println!("encode_aead({}):", label);
        println!("  ciphertext = {}", hex(&packet.ciphertext));
        println!("  commitment = {}", hex(&packet.commitment.mac));
        // Verify roundtrip
        let recovered = decode_aead(secret, &packet).unwrap();
        assert_eq!(&recovered, plaintext, "AEAD roundtrip failed for {}", label);
        println!("  roundtrip   = OK");
    }
    println!();

    // ── RopeRatchet with fixed snapshots ──
    println!("## RopeRatchet::advance_with_snapshot\n");
    let mut ratchet = RopeRatchet::new(b"session-secret", b"alice-to-bob").unwrap();
    for i in 0..3u8 {
        let snap = make_snapshot(i);
        let (key, step) = ratchet.advance_with_snapshot(snap).unwrap();
        println!("ratchet_step_{}: key={} counter={}", i, hex(&key), step.counter);
    }
    println!();

    println!("═══════════════════════════════════════════════════════════");
    println!("  ALL VECTORS GENERATED SUCCESSFULLY");
    println!("═══════════════════════════════════════════════════════════");
}
