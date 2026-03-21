// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! KK, Keeney Kode: Basic Usage Example
//!
//! Demonstrates the core KK primitive:
//!   - Encoding: symbol values become functions of the universe
//!   - Decoding: same secret + transmitted entropy = recovery
//!   - Temporal uniqueness: same message, different moments, different ciphertext

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  KK, Keeney Kode                                      ║");
    println!("║  A novel cryptographic primitive                        ║");
    println!("║  J.A. Keeney, Australia, 2026                    ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    let shared_secret = b"demo-shared-secret-2026";
    let message = b"Hello from KK! This language only exists for one cosmic instant.";

    // ─── ENCODE ────────────────────────────────────────────────
    println!("[ENCODE] Capturing entropic moment...");
    let packet = kk_crypto::encode(shared_secret, message).unwrap();

    println!("[ENCODE] Message:    {:?}", std::str::from_utf8(message).unwrap());
    println!("[ENCODE] Ciphertext: {} bytes", packet.ciphertext.len());
    println!(
        "[ENCODE] Entropy ε:  {}...",
        hex::encode(&packet.entropy_snapshot.bytes[..8])
    );
    println!(
        "[ENCODE] Timestamp:  {} ns since epoch",
        packet.entropy_snapshot.timestamp_nanos
    );
    println!(
        "[ENCODE] Commitment: {}...",
        hex::encode(&packet.commitment.mac[..8])
    );
    println!();

    // ─── TEMPORAL UNIQUENESS ───────────────────────────────────
    println!("[KK PROPERTY] Demonstrating temporal uniqueness:");
    println!("  Encoding the letter 'A' five times...");
    for i in 1..=5 {
        let p = kk_crypto::encode(shared_secret, b"A").unwrap();
        println!(
            "  KK('A') at T{i} = 0x{} (ε = {}...)",
            hex::encode(&p.ciphertext),
            hex::encode(&p.entropy_snapshot.bytes[..4])
        );
    }
    println!("  → Same symbol, five different cosmic instants, five unrelated values.");
    println!();

    // ─── WIRE TRANSMISSION ─────────────────────────────────────
    println!("[TRANSMIT] Serializing packet for transmission...");
    let wire_bytes = packet.to_bytes();
    println!("[TRANSMIT] Wire format: {} bytes", wire_bytes.len());
    println!();

    // ─── DECODE ────────────────────────────────────────────────
    println!("[DECODE] Receiver deserializes packet...");
    let received = kk_crypto::KkPacket::from_bytes(&wire_bytes).unwrap();

    println!("[DECODE] Verifying temporal commitment...");
    let plaintext = kk_crypto::decode(shared_secret, &received).unwrap();

    println!(
        "[DECODE] Recovered: {:?}",
        std::str::from_utf8(&plaintext).unwrap()
    );
    println!();

    assert_eq!(message.as_slice(), plaintext.as_slice());

    // ─── WRONG KEY DEMO ────────────────────────────────────────
    println!("[ATTACK] Attempting decode with wrong key...");
    match kk_crypto::decode(b"wrong-key-attacker", &received) {
        Err(e) => println!("[ATTACK] Failed: {e}"),
        Ok(_) => println!("[ATTACK] This should never happen!"),
    }
    println!();

    println!("════════════════════════════════════════════════════════════");
    println!("  KK: The language the message was written in");
    println!("  only existed for one cosmic instant, and is now gone.");
    println!("════════════════════════════════════════════════════════════");
}
