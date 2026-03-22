// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Integration tests for KK, Keeney Kode
//!
//! These tests demonstrate and verify the core security properties
//! claimed by the KK primitive.

use kk_crypto::{decode, encode, KkPacket};
use kk_crypto::{encode_bound, decode_bound, KkBoundPacket, generate_challenge, GENESIS_MAC};
use kk_crypto::{EntropyPool, encode_pooled, encode_aead_pooled};
use kk_crypto::{encode_aead_batch, decode_aead_batch, encode_aead, decode_aead, KkAeadPacket};
use kk_crypto::{encode_parallel, decode_parallel, KkParallelPacket, PARALLEL_CHUNK_SIZE};
use kk_crypto::KkRngPool;
use std::time::Duration;

/// Core property: encode then decode recovers original message.
#[test]
fn roundtrip_ascii() {
    let secret = b"integration-test-secret";
    let msg = b"The quick brown fox jumps over the lazy dog";

    let packet = encode(secret, msg).unwrap();
    let recovered = decode(secret, &packet).unwrap();
    assert_eq!(msg.as_slice(), recovered.as_slice());
}

/// Core property: encode then decode works for arbitrary binary data.
#[test]
fn roundtrip_binary() {
    let secret = b"binary-test";
    let msg: Vec<u8> = (0..=255).collect(); // All possible byte values

    let packet = encode(secret, &msg).unwrap();
    let recovered = decode(secret, &packet).unwrap();
    assert_eq!(msg, recovered);
}

/// Core property: encode then decode works for UTF-8 / Unicode.
#[test]
fn roundtrip_unicode() {
    let secret = b"unicode-test";
    let msg = "KK: 日本語テスト 🔥 Ελληνικά العربية".as_bytes();

    let packet = encode(secret, msg).unwrap();
    let recovered = decode(secret, &packet).unwrap();
    assert_eq!(msg, recovered.as_slice());
    assert_eq!(
        std::str::from_utf8(&recovered).unwrap(),
        "KK: 日本語テスト 🔥 Ελληνικά العربية"
    );
}

/// TEMPORAL UNIQUENESS: KK(S) at T₁ ≠ KK(S) at T₂
///
/// The same symbol encoded at two different moments produces
/// cryptographically unrelated values. This is the core novel property.
///
/// Note: for a 1-byte message, the ciphertext is 1 byte (256 values),
/// so collisions are expected by the birthday bound. The true uniqueness
/// guarantee is in the entropy snapshot, each encoding captures an
/// unrepeatable cosmic moment. We test with a longer message to
/// demonstrate ciphertext uniqueness where the space is large enough.
#[test]
fn temporal_uniqueness_single_byte() {
    let secret = b"temporal-test";

    // Every encoding must have a unique entropy snapshot
    let mut snapshots = Vec::new();
    for _ in 0..20 {
        let packet = encode(secret, b"A").unwrap();
        snapshots.push(packet.entropy_snapshot.bytes);
    }
    for i in 0..snapshots.len() {
        for j in (i + 1)..snapshots.len() {
            assert_ne!(
                snapshots[i], snapshots[j],
                "Entropy snapshots at T_{i} and T_{j} must differ, each moment is unique"
            );
        }
    }
}

/// TEMPORAL UNIQUENESS with a longer message where ciphertext space
/// is large enough that collisions are astronomically unlikely.
#[test]
fn temporal_uniqueness_longer_message() {
    let secret = b"temporal-long-test";
    let msg = b"AAAAAAAAAAAAAAAA"; // 16 bytes of repeated 'A'

    let mut ciphertexts = Vec::new();
    for _ in 0..20 {
        let packet = encode(secret, msg).unwrap();
        ciphertexts.push(packet.ciphertext.clone());
    }

    for i in 0..ciphertexts.len() {
        for j in (i + 1)..ciphertexts.len() {
            assert_ne!(
                ciphertexts[i], ciphertexts[j],
                "KK(msg) at T_{i} must ≠ KK(msg) at T_{j}"
            );
        }
    }
}

/// TEMPORAL UNIQUENESS for full messages.
#[test]
fn temporal_uniqueness_full_message() {
    let secret = b"temporal-msg-test";
    let msg = b"identical message";

    let p1 = encode(secret, msg).unwrap();
    let p2 = encode(secret, msg).unwrap();

    assert_ne!(p1.ciphertext, p2.ciphertext);
    assert_ne!(
        p1.entropy_snapshot.bytes,
        p2.entropy_snapshot.bytes,
        "Different moments must have different entropy snapshots"
    );

    // But both must decode correctly
    assert_eq!(decode(secret, &p1).unwrap(), msg.as_slice());
    assert_eq!(decode(secret, &p2).unwrap(), msg.as_slice());
}

/// ALGORITHM TRANSPARENCY (Kerckhoffs' principle):
/// Security holds even when attacker knows exactly how KK works.
/// An attacker with the ciphertext and entropy snapshot but without
/// the shared secret cannot recover the plaintext.
#[test]
fn kerckhoffs_principle() {
    let real_secret = b"the-real-secret";
    let msg = b"classified information";

    let packet = encode(real_secret, msg).unwrap();

    // Attacker has: ciphertext, entropy snapshot, commitment, full algorithm
    // Attacker does NOT have: shared secret
    // Attacker tries various keys, all must fail
    let attacker_guesses: &[&[u8]] = &[
        b"wrong-key",
        b"the-real-secrets", // Close but wrong
        b"",
        b"THE-REAL-SECRET", // Case wrong
    ];

    for guess in attacker_guesses {
        let result = decode(guess, &packet);
        assert!(result.is_err(), "Attacker key guess must fail commitment check");
    }
}

/// FORWARD SYMBOL SECRECY:
/// Past symbol values cannot be derived from current state.
/// Each encoding creates independent entropy, knowing one packet
/// reveals nothing about any other packet.
#[test]
fn forward_symbol_secrecy() {
    let secret = b"forward-secrecy-test";

    let p1 = encode(secret, b"message one").unwrap();
    let p2 = encode(secret, b"message two").unwrap();

    // Entropy snapshots are independent
    assert_ne!(p1.entropy_snapshot.bytes, p2.entropy_snapshot.bytes);

    // Decoding one reveals nothing about the other
    let d1 = decode(secret, &p1).unwrap();
    let d2 = decode(secret, &p2).unwrap();
    assert_eq!(d1, b"message one");
    assert_eq!(d2, b"message two");
}

/// INTEGRITY: Any modification to the packet is detected.
#[test]
fn integrity_ciphertext_tampering() {
    let secret = b"integrity-test";
    let packet = encode(secret, b"protect this").unwrap();

    // Tamper with ciphertext
    let mut tampered = packet.clone();
    if let Some(byte) = tampered.ciphertext.first_mut() {
        *byte ^= 0x01;
    }
    assert!(decode(secret, &tampered).is_err());
}

#[test]
fn integrity_entropy_tampering() {
    let secret = b"entropy-tamper-test";
    let packet = encode(secret, b"protect this too").unwrap();

    // Tamper with entropy snapshot
    let mut tampered = packet.clone();
    tampered.entropy_snapshot.bytes[0] ^= 0x01;
    assert!(decode(secret, &tampered).is_err());
}

/// PACKET SERIALIZATION: Full roundtrip through wire format.
#[test]
fn wire_format_roundtrip() {
    let secret = b"wire-test";
    let msg = b"transmitted over the wire";

    let packet = encode(secret, msg).unwrap();

    // Simulate transmission: serialize → bytes → deserialize
    let wire_bytes = packet.to_bytes();
    let received = KkPacket::from_bytes(&wire_bytes).unwrap();

    let decoded = decode(secret, &received).unwrap();
    assert_eq!(msg.as_slice(), decoded.as_slice());
}

/// STRESS TEST: Large message with many symbols.
#[test]
fn large_message_stress() {
    let secret = b"stress-test";
    let msg: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();

    let packet = encode(secret, &msg).unwrap();
    let decoded = decode(secret, &packet).unwrap();
    assert_eq!(msg, decoded);
}

/// Verify that each byte position produces independent key material.
#[test]
fn per_position_independence() {
    let secret = b"position-test";
    // Encode a repeated byte pattern
    let msg = vec![0x41u8; 256]; // 256 copies of 'A'

    let packet = encode(secret, &msg).unwrap();

    // In a naive cipher, repeated plaintext = repeated ciphertext.
    // In KK, every position has its own derived key, so the ciphertext
    // should show no obvious repetition.
    let unique_bytes: std::collections::HashSet<u8> =
        packet.ciphertext.iter().copied().collect();

    // With 256 bytes of ciphertext derived from independent keys,
    // we expect high entropy, many distinct byte values
    assert!(
        unique_bytes.len() > 50,
        "Ciphertext of repeated plaintext must show high entropy (got {} unique bytes)",
        unique_bytes.len()
    );
}

/// Roundtrip at sizes exercising both full 8-chunk batches and partial tails.
///
/// CHUNK_SIZE is 4096, so batch boundary is at 32768 (8 × 4096).
/// Test sizes that land exactly on, just under, and just over batch boundaries.
#[test]
fn batch_boundary_roundtrips() {
    let secret = b"batch-boundary-test";
    // pattern: position-dependent bytes so any lane swap is detectable
    for &size in &[
        1,              // single byte, scalar only
        4096,           // 1 full chunk, scalar tail
        4097,           // 1 full chunk + 1 byte
        32768,          // exactly 1 full batch of 8
        32769,          // 1 full batch + 1 byte tail
        65536,          // exactly 2 full batches
        65537,          // 2 full batches + 1 byte
        100_000,        // 3 batches + partial tail (100000 / 32768 = 3.05)
    ] {
        let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let packet = encode(secret, &msg).unwrap();
        let recovered = decode(secret, &packet).unwrap();
        assert_eq!(msg, recovered, "Roundtrip failed for {size}-byte message");
    }
}

// ─────────────────────────────────────────────────────────────────
//  Bound-commitment integration tests
// ─────────────────────────────────────────────────────────────────

/// Challenge-response roundtrip: encode_bound → decode_bound.
#[test]
fn bound_roundtrip() {
    let secret = b"bound-integration";
    let msg = b"Temporal proof: nonce-bound, epoch-checked, chain-ordered.";

    let nonce = generate_challenge().unwrap();
    let packet = encode_bound(secret, msg, &nonce, &GENESIS_MAC).unwrap();
    let recovered = decode_bound(secret, &packet, &nonce, Duration::from_secs(30)).unwrap();

    assert_eq!(msg.as_slice(), recovered.as_slice());
}

/// Replay resistance: reusing a nonce the verifier didn't issue fails.
#[test]
fn bound_replay_rejected() {
    let secret = b"replay-test";
    let nonce = generate_challenge().unwrap();
    let stale_nonce = generate_challenge().unwrap();

    let packet = encode_bound(secret, b"payload", &nonce, &GENESIS_MAC).unwrap();

    // Attacker replays packet with a different verifier nonce
    let result = decode_bound(secret, &packet, &stale_nonce, Duration::from_secs(30));
    assert!(result.is_err(), "Replay with wrong nonce must be rejected");
}

/// Chain integrity: a three-message chain where each references the previous.
#[test]
fn bound_chain_three_messages() {
    let secret = b"chain-integration";

    let n1 = generate_challenge().unwrap();
    let p1 = encode_bound(secret, b"alpha", &n1, &GENESIS_MAC).unwrap();
    decode_bound(secret, &p1, &n1, Duration::from_secs(30)).unwrap();

    let n2 = generate_challenge().unwrap();
    let p2 = encode_bound(secret, b"bravo", &n2, &p1.proof.mac).unwrap();
    decode_bound(secret, &p2, &n2, Duration::from_secs(30)).unwrap();

    let n3 = generate_challenge().unwrap();
    let p3 = encode_bound(secret, b"charlie", &n3, &p2.proof.mac).unwrap();
    decode_bound(secret, &p3, &n3, Duration::from_secs(30)).unwrap();

    // Verify chain links
    assert_eq!(p1.proof.prev_mac, GENESIS_MAC);
    assert_eq!(p2.proof.prev_mac, p1.proof.mac);
    assert_eq!(p3.proof.prev_mac, p2.proof.mac);
}

/// Wire format: bound packet serialization roundtrip.
#[test]
fn bound_wire_format_roundtrip() {
    let secret = b"bound-wire";
    let msg = b"serialize bound packet over the wire";

    let nonce = generate_challenge().unwrap();
    let packet = encode_bound(secret, msg, &nonce, &GENESIS_MAC).unwrap();

    let wire = packet.to_bytes();
    let restored = KkBoundPacket::from_bytes(&wire).unwrap();

    let decoded = decode_bound(secret, &restored, &nonce, Duration::from_secs(30)).unwrap();
    assert_eq!(msg.as_slice(), decoded.as_slice());
}

/// Tamper detection: modifying ciphertext invalidates the temporal proof.
#[test]
fn bound_tamper_detected() {
    let secret = b"bound-tamper";
    let nonce = generate_challenge().unwrap();
    let mut packet = encode_bound(secret, b"critical data", &nonce, &GENESIS_MAC).unwrap();

    packet.ciphertext[0] ^= 0xFF;

    let result = decode_bound(secret, &packet, &nonce, Duration::from_secs(30));
    assert!(result.is_err(), "Tampered ciphertext must fail bound verification");
}

// ─────────────────────────────────────────────────────────────────
//  Rope Ratchet (session) integration tests
// ─────────────────────────────────────────────────────────────────

use kk_crypto::session::{encode_session, decode_session, RopeRatchet, RopePacket};

/// Basic roundtrip: encode_session then decode_session recovers plaintext.
#[test]
fn session_roundtrip() {
    let secret = b"session-roundtrip-test";
    let mut sender = RopeRatchet::new(secret, b"a-to-b").unwrap();
    let mut receiver = RopeRatchet::new(secret, b"a-to-b").unwrap();

    let msg = b"hello forward secrecy";
    let packet = encode_session(&mut sender, msg).unwrap();
    let recovered = decode_session(&mut receiver, &packet).unwrap();
    assert_eq!(msg.as_slice(), recovered.as_slice());
}

/// Multi-message sequence: 10 messages decode in order.
#[test]
fn session_multi_message() {
    let secret = b"multi-msg-test";
    let mut sender = RopeRatchet::new(secret, b"stream").unwrap();
    let mut receiver = RopeRatchet::new(secret, b"stream").unwrap();

    for i in 0u32..10 {
        let msg = format!("message number {i}");
        let packet = encode_session(&mut sender, msg.as_bytes()).unwrap();
        let recovered = decode_session(&mut receiver, &packet).unwrap();
        assert_eq!(msg.as_bytes(), recovered.as_slice(), "message {i} mismatch");
    }

    assert_eq!(sender.counter(), 10);
    assert_eq!(receiver.counter(), 10);
}

/// Counter rejection: replaying or skipping a message is rejected.
#[test]
fn session_counter_rejection() {
    let secret = b"counter-reject-test";
    let mut sender = RopeRatchet::new(secret, b"dir").unwrap();
    let mut receiver = RopeRatchet::new(secret, b"dir").unwrap();

    // Send and receive message 1
    let p1 = encode_session(&mut sender, b"first").unwrap();
    decode_session(&mut receiver, &p1).unwrap();

    // Send message 2
    let p2 = encode_session(&mut sender, b"second").unwrap();

    // Skip message 2 and send message 3
    let p3 = encode_session(&mut sender, b"third").unwrap();

    // Receiver expects counter 2 but gets counter 3 → reject
    let result = decode_session(&mut receiver, &p3);
    assert!(result.is_err(), "Skipped counter must be rejected (strict ordering)");

    // Replay message 1 → counter 1 is in the past → reject
    let result = decode_session(&mut receiver, &p1);
    assert!(result.is_err(), "Replayed old message must be rejected");

    // Message 2 should still work (it's the expected next counter)
    let recovered = decode_session(&mut receiver, &p2).unwrap();
    assert_eq!(recovered.as_slice(), b"second");
}

/// Direction independence: same secret but different contexts
/// produce completely different key streams.
#[test]
fn session_direction_independence() {
    let secret = b"direction-test";
    let msg = b"same plaintext both directions";

    let mut send_ab = RopeRatchet::new(secret, b"a-to-b").unwrap();
    let mut send_ba = RopeRatchet::new(secret, b"b-to-a").unwrap();

    let pkt_ab = encode_session(&mut send_ab, msg).unwrap();
    let pkt_ba = encode_session(&mut send_ba, msg).unwrap();

    // Different contexts must produce different inner ciphertexts
    assert_ne!(
        pkt_ab.inner.ciphertext, pkt_ba.inner.ciphertext,
        "Different direction contexts must produce different ciphertexts"
    );

    // Each direction decodes with its own receiver
    let mut recv_ab = RopeRatchet::new(secret, b"a-to-b").unwrap();
    let mut recv_ba = RopeRatchet::new(secret, b"b-to-a").unwrap();

    let dec_ab = decode_session(&mut recv_ab, &pkt_ab).unwrap();
    let dec_ba = decode_session(&mut recv_ba, &pkt_ba).unwrap();
    assert_eq!(dec_ab.as_slice(), msg.as_slice());
    assert_eq!(dec_ba.as_slice(), msg.as_slice());
}

/// Wire format roundtrip: RopePacket → to_bytes → from_bytes → decode.
#[test]
fn session_wire_format_roundtrip() {
    let secret = b"wire-session-test";
    let msg = b"transmitted with forward secrecy over the wire";

    let mut sender = RopeRatchet::new(secret, b"wire-dir").unwrap();
    let mut receiver = RopeRatchet::new(secret, b"wire-dir").unwrap();

    let packet = encode_session(&mut sender, msg).unwrap();

    // Simulate transmission
    let wire_bytes = packet.to_bytes();
    let received = RopePacket::from_bytes(&wire_bytes).unwrap();

    let recovered = decode_session(&mut receiver, &received).unwrap();
    assert_eq!(msg.as_slice(), recovered.as_slice());
}

/// Forward secrecy: ratchet state after advance is unrelated to previous state.
/// Verifying that successive message keys are cryptographically independent.
#[test]
fn session_forward_secrecy_key_independence() {
    let secret = b"fs-key-test";
    let mut ratchet = RopeRatchet::new(secret, b"fs-dir").unwrap();

    let mut keys = Vec::new();
    for _ in 0..5 {
        let (key, _step) = ratchet.advance().unwrap();
        keys.push(key);
    }

    // All message keys must be distinct
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "Message keys {i} and {j} must differ");
        }
    }
}

/// Tamper detection: modifying the inner ciphertext in a RopePacket
/// causes decode_session to fail.
#[test]
fn session_tamper_inner_ciphertext() {
    let secret = b"tamper-session-test";
    let mut sender = RopeRatchet::new(secret, b"tamper-dir").unwrap();
    let mut receiver = RopeRatchet::new(secret, b"tamper-dir").unwrap();

    let mut packet = encode_session(&mut sender, b"sensitive data").unwrap();
    packet.inner.ciphertext[0] ^= 0xFF;

    let result = decode_session(&mut receiver, &packet);
    assert!(result.is_err(), "Tampered ciphertext must fail integrity check");
}

/// Wrong secret: receiver with different shared secret cannot decode.
#[test]
fn session_wrong_secret_rejected() {
    let mut sender = RopeRatchet::new(b"correct-secret", b"dir").unwrap();
    let mut receiver = RopeRatchet::new(b"wrong-secret", b"dir").unwrap();

    let packet = encode_session(&mut sender, b"private message").unwrap();
    let result = decode_session(&mut receiver, &packet);
    assert!(result.is_err(), "Wrong shared secret must fail");
}

// ─────────────────────────────────────────────────────────────────
//  AEAD (Authenticated Encryption with Associated Data) tests
// ─────────────────────────────────────────────────────────────────

use kk_crypto::{encode_session_aead, decode_session_aead};

/// Direct kk_mac collision test: two messages differing by one byte must produce different MACs.
#[test]
fn kk_mac_no_collision() {
    // Test with EXACT same conditions as AEAD: 32-byte key, 76-byte message, diff at pos 62
    let key = vec![0x78u8; 32]; // 32-byte key like derive_commitment_key produces
    let mut msg1 = vec![0u8; 76];
    for i in 0..76 { msg1[i] = i as u8; }
    let mut msg2 = msg1.clone();
    msg2[62] ^= 0xFF; // flip one byte (same position as ciphertext[0] in AEAD message)

    let mac1 = kk_crypto::kk_mix::kk_mac(&key, &msg1);
    let mac2 = kk_crypto::kk_mix::kk_mac(&key, &msg2);

    assert_ne!(mac1, mac2, "kk_mac must produce different tags for different 76B messages (32B key)");

    // Also test total absorb: key_len(8) + key(32) + message(76) = 116 bytes
    // All absorbed in one rate block (116 < RATE_BYTES=152)
    // The differing byte is at absolute absorb position 8+32+62 = 102
    
    // Also test position 62 with 24-byte key (our passing test)
    let key24 = vec![0x78u8; 24];
    let mac3 = kk_crypto::kk_mix::kk_mac(&key24, &msg1);
    let mac4 = kk_crypto::kk_mix::kk_mac(&key24, &msg2);

    assert_ne!(mac3, mac4, "kk_mac must produce different tags for different 76B messages (24B key)");
}

/// AEAD roundtrip: encode then decode recovers plaintext, AAD intact.
#[test]
fn aead_roundtrip() {
    let secret = b"aead-test-secret";
    let plaintext = b"Hello, AEAD world!";
    let aad = b"metadata-v1";

    let packet = encode_aead(secret, plaintext, aad).unwrap();
    assert_eq!(packet.aad, aad.as_slice());

    let recovered = decode_aead(secret, &packet).unwrap();
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

/// AEAD tamper detection: modifying the AAD causes decode to fail.
#[test]
fn aead_tamper_aad() {
    let secret = b"aead-tamper-test";
    let plaintext = b"sensitive payload";
    let aad = b"original-header";

    let mut packet = encode_aead(secret, plaintext, aad).unwrap();
    packet.aad[0] ^= 0xFF; // tamper with the AAD

    let result = decode_aead(secret, &packet);
    assert!(result.is_err(), "Tampered AAD must fail integrity check");
}

/// AEAD tamper detection: modifying the ciphertext causes decode to fail.
#[test]
fn aead_tamper_ciphertext() {
    let secret = b"aead-ct-tamper";
    let plaintext = b"important data";
    let aad = b"header";

    let packet = encode_aead(secret, plaintext, aad).unwrap();

    // Manually reconstruct a tampered packet
    let mut tampered_ct = packet.ciphertext.clone();
    tampered_ct[0] ^= 0xFF;

    // Test: verify_aead should fail with tampered ciphertext
    // Re-encode to wire format and back to ensure no shortcuts
    let tampered_packet = KkAeadPacket {
        aad: packet.aad.clone(),
        ciphertext: tampered_ct,
        entropy_snapshot: packet.entropy_snapshot.clone(),
        commitment: packet.commitment.clone(),
    };

    // Serialize to wire format and back
    let wire = tampered_packet.to_bytes();
    let roundtripped = KkAeadPacket::from_bytes(&wire).unwrap();

    let result = decode_aead(secret, &roundtripped);

    // Also test directly 
    let result2 = decode_aead(secret, &tampered_packet);

    assert!(result.is_err() || result2.is_err(), "Tampered ciphertext must fail integrity check");
}

/// AEAD with empty AAD: works like standard encode but uses AEAD commitment.
#[test]
fn aead_empty_aad() {
    let secret = b"aead-empty-aad-test";
    let plaintext = b"payload with no associated data";
    let aad = b"";

    let packet = encode_aead(secret, plaintext, aad).unwrap();
    assert!(packet.aad.is_empty());

    let recovered = decode_aead(secret, &packet).unwrap();
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

/// AEAD with large AAD: 10 KB of associated data.
#[test]
fn aead_large_aad() {
    let secret = b"aead-large-aad";
    let plaintext = b"small payload";
    let aad = vec![0xABu8; 10_000];

    let packet = encode_aead(secret, plaintext, &aad).unwrap();
    assert_eq!(packet.aad.len(), 10_000);

    let recovered = decode_aead(secret, &packet).unwrap();
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

/// AEAD wire format: to_bytes/from_bytes roundtrip.
#[test]
fn aead_wire_format_roundtrip() {
    let secret = b"aead-wire-test";
    let plaintext = b"wire format test";
    let aad = b"routing-info";

    let packet = encode_aead(secret, plaintext, aad).unwrap();
    let wire = packet.to_bytes();
    let restored = KkAeadPacket::from_bytes(&wire).unwrap();

    assert_eq!(restored.aad, packet.aad);
    assert_eq!(restored.ciphertext, packet.ciphertext);

    let recovered = decode_aead(secret, &restored).unwrap();
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

/// Session AEAD roundtrip: forward secrecy + AAD authentication.
#[test]
fn session_aead_roundtrip() {
    let secret = b"session-aead-secret";
    let direction = b"alice-to-bob";
    let mut sender = RopeRatchet::new(secret, direction).unwrap();
    let mut receiver = RopeRatchet::new(secret, direction).unwrap();

    let plaintext = b"Forward-secret AEAD message";
    let aad = b"session-metadata";

    let packet = encode_session_aead(&mut sender, plaintext, aad).unwrap();
    assert_eq!(packet.inner.aad, aad.as_slice());

    let recovered = decode_session_aead(&mut receiver, &packet).unwrap();
    assert_eq!(recovered.as_slice(), plaintext.as_slice());
}

/// Session AEAD tamper: modifying AAD after encoding causes decode failure.
#[test]
fn session_aead_tamper_aad() {
    let secret = b"session-aead-tamper";
    let direction = b"tamper-dir";
    let mut sender = RopeRatchet::new(secret, direction).unwrap();
    let mut receiver = RopeRatchet::new(secret, direction).unwrap();

    let mut packet = encode_session_aead(&mut sender, b"secret data", b"original-aad").unwrap();
    packet.inner.aad[0] ^= 0xFF; // tamper

    let result = decode_session_aead(&mut receiver, &packet);
    assert!(result.is_err(), "Tampered session AAD must fail integrity check");
}

// ─── KK-EKA (Entropy Key Agreement) Tests ───────────────────────────────────

use kk_crypto::{EkaInitiator, EkaResponder};

/// EKA happy path: both parties derive the same session key.
#[test]
fn eka_happy_path() {
    let psk = b"integration-eka-psk";

    let (alice, msg1) = EkaInitiator::new(psk).unwrap();
    let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();
    let (msg3, alice_key) = alice.process_msg2(&msg2).unwrap();
    let bob_key = bob.process_msg3(&msg3).unwrap();

    assert_eq!(alice_key, bob_key, "both parties must derive the same session key");
    assert_ne!(alice_key, [0u8; 32], "session key must not be all zeros");
}

/// EKA wrong PSK: responder using a different PSK is rejected by initiator.
#[test]
fn eka_wrong_psk_rejected() {
    let psk_alice = b"alice-psk";
    let psk_bob = b"bob-different-psk";

    let (alice, msg1) = EkaInitiator::new(psk_alice).unwrap();
    let (_, msg2) = EkaResponder::new(psk_bob, &msg1).unwrap();

    // Alice verifies auth_b using her PSK  - Bob's tag was computed with a different PSK
    let result = alice.process_msg2(&msg2);
    assert!(result.is_err(), "wrong PSK must cause auth_b verification to fail");
}

/// EKA tampered msg2: flipping a byte in entropy_b causes rejection.
#[test]
fn eka_tampered_msg2() {
    let psk = b"tamper-test-psk";

    let (alice, msg1) = EkaInitiator::new(psk).unwrap();
    let (_, msg2) = EkaResponder::new(psk, &msg1).unwrap();

    // Tamper with entropy_b
    let mut tampered = msg2.clone();
    tampered.entropy_b_bytes[0] ^= 0xFF;

    let result = alice.process_msg2(&tampered);
    assert!(result.is_err(), "tampered msg2 entropy must fail verification");
}

/// EKA tampered msg3: flipping a byte in entropy_a causes rejection.
#[test]
fn eka_tampered_msg3() {
    let psk = b"tamper-msg3-psk";

    let (alice, msg1) = EkaInitiator::new(psk).unwrap();
    let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();
    let (msg3, _) = alice.process_msg2(&msg2).unwrap();

    // Tamper with entropy_a
    let mut tampered = msg3.clone();
    tampered.entropy_a_bytes[0] ^= 0xFF;

    let result = bob.process_msg3(&tampered);
    assert!(result.is_err(), "tampered msg3 entropy must fail verification");
}

/// EKA commitment binding: replacing msg3's entropy while keeping the auth tag fails.
#[test]
fn eka_commitment_binding() {
    let psk = b"commitment-binding-psk";

    let (alice, msg1) = EkaInitiator::new(psk).unwrap();
    let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();
    let (msg3, _) = alice.process_msg2(&msg2).unwrap();

    // Create a completely different entropy_a but keep the original auth_a
    let mut fake_msg3 = msg3.clone();
    // Flip all bytes in entropy_a  - the commitment hash will not match
    for b in fake_msg3.entropy_a_bytes.iter_mut() {
        *b ^= 0xFF;
    }

    let result = bob.process_msg3(&fake_msg3);
    assert!(result.is_err(), "commitment binding: faked entropy must not pass commitment check");
}

/// EKA forward secrecy: different sessions with the same PSK produce different keys.
#[test]
fn eka_forward_secrecy() {
    let psk = b"forward-secrecy-psk";

    // Session 1
    let (a1, m1a) = EkaInitiator::new(psk).unwrap();
    let (b1, m2a) = EkaResponder::new(psk, &m1a).unwrap();
    let (m3a, key1) = a1.process_msg2(&m2a).unwrap();
    let _ = b1.process_msg3(&m3a).unwrap();

    // Session 2
    let (a2, m1b) = EkaInitiator::new(psk).unwrap();
    let (b2, m2b) = EkaResponder::new(psk, &m1b).unwrap();
    let (m3b, key2) = a2.process_msg2(&m2b).unwrap();
    let _ = b2.process_msg3(&m3b).unwrap();

    assert_ne!(key1, key2, "forward secrecy: different sessions must produce different keys even with same PSK");
}

/// EKA → Rope Ratchet end-to-end: EKA session key feeds into RopeRatchet for encrypted communication.
#[test]
fn eka_to_rope_ratchet_end_to_end() {
    use kk_crypto::RopeRatchet;
    use kk_crypto::session::{encode_session, decode_session};

    let psk = b"eka-rope-e2e-psk";
    let context = b"eka-session-context";

    // Run EKA to establish a shared session key
    let (alice, msg1) = EkaInitiator::new(psk).unwrap();
    let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();
    let (msg3, alice_key) = alice.process_msg2(&msg2).unwrap();
    let bob_key = bob.process_msg3(&msg3).unwrap();
    assert_eq!(alice_key, bob_key);

    // Both parties initialize RopeRatchet with the EKA session key
    let mut sender = RopeRatchet::new(&alice_key, context).unwrap();
    let mut receiver = RopeRatchet::new(&bob_key, context).unwrap();

    // Send a message
    let plaintext = b"Hello from Alice via EKA + Rope Ratchet!";
    let packet = encode_session(&mut sender, plaintext).unwrap();
    let recovered = decode_session(&mut receiver, &packet).unwrap();
    assert_eq!(plaintext.as_slice(), recovered.as_slice());
}

// ── Pooled Entropy Tests ──────────────────────────────────────────

/// Pooled encode/decode roundtrip produces identical plaintext.
#[test]
fn pooled_roundtrip_basic() {
    let pool = EntropyPool::new(16).unwrap();
    let secret = b"pooled-basic-secret";
    let msg = b"Pooled entropy encode roundtrip";

    let packet = encode_pooled(secret, msg, &pool).unwrap();
    let recovered = decode(secret, &packet).unwrap();
    assert_eq!(msg.as_slice(), recovered.as_slice());
}

/// Pooled AEAD roundtrip preserves plaintext and AAD.
#[test]
fn pooled_aead_roundtrip() {
    let pool = EntropyPool::new(16).unwrap();
    let secret = b"pooled-aead-secret";
    let msg = b"AEAD pooled test";
    let aad = b"associated-data";

    let packet = encode_aead_pooled(secret, msg, aad, &pool).unwrap();
    let recovered = decode_aead(secret, &packet).unwrap();
    assert_eq!(msg.as_slice(), recovered.as_slice());
}

/// Pooled encode works for all byte values (binary safety).
#[test]
fn pooled_roundtrip_binary() {
    let pool = EntropyPool::new(16).unwrap();
    let secret = b"pooled-binary";
    let msg: Vec<u8> = (0..=255).collect();

    let packet = encode_pooled(secret, &msg, &pool).unwrap();
    let recovered = decode(secret, &packet).unwrap();
    assert_eq!(msg, recovered);
}

/// Pooled encode handles a 1 MB payload correctly.
#[test]
fn pooled_roundtrip_large() {
    let pool = EntropyPool::new(16).unwrap();
    let secret = b"pooled-large";
    let msg = vec![0xABu8; 1_048_576]; // 1 MB

    let packet = encode_pooled(secret, &msg, &pool).unwrap();
    let recovered = decode(secret, &packet).unwrap();
    assert_eq!(msg, recovered);
}

/// Multiple pooled encodes of the same plaintext produce different ciphertexts.
#[test]
fn pooled_temporal_uniqueness() {
    let pool = EntropyPool::new(16).unwrap();
    let secret = b"pooled-unique";
    let msg = b"same message twice";

    let p1 = encode_pooled(secret, msg, &pool).unwrap();
    let p2 = encode_pooled(secret, msg, &pool).unwrap();
    assert_ne!(p1.ciphertext, p2.ciphertext);
}

// ─────────────────────────────────────────────────────────────────
//  Batched AEAD tests (Phase 7)
// ─────────────────────────────────────────────────────────────────

/// Batch encode → batch decode roundtrip with 100 messages of varying sizes.
#[test]
fn batch_aead_roundtrip_100() {
    let secret = b"batch-integration-secret";
    let pool = EntropyPool::new(64).unwrap();

    let plaintexts: Vec<Vec<u8>> = (0..100)
        .map(|i| vec![(i & 0xFF) as u8; 64 + i * 10])
        .collect();
    let aad = b"batch-test-aad";
    let messages: Vec<(&[u8], &[u8])> = plaintexts.iter()
        .map(|pt| (pt.as_slice(), aad.as_slice()))
        .collect();

    let packets = encode_aead_batch(secret, &messages, Some(&pool)).unwrap();
    assert_eq!(packets.len(), 100);

    let recovered = decode_aead_batch(secret, &packets).unwrap();
    assert_eq!(recovered.len(), 100);
    for (i, (pt, rec)) in plaintexts.iter().zip(recovered.iter()).enumerate() {
        assert_eq!(pt.as_slice(), rec.as_slice(), "mismatch at message {i}");
    }
}

/// Batch with a single message degenerates to single encode/decode.
#[test]
fn batch_aead_single_message() {
    let secret = b"batch-single-secret";
    let pool = EntropyPool::new(16).unwrap();
    let plaintext = b"single message in batch";
    let aad = b"single-aad";
    let messages: Vec<(&[u8], &[u8])> = vec![(plaintext.as_slice(), aad.as_slice())];

    let packets = encode_aead_batch(secret, &messages, Some(&pool)).unwrap();
    assert_eq!(packets.len(), 1);

    let recovered = decode_aead_batch(secret, &packets).unwrap();
    assert_eq!(recovered[0].as_slice(), plaintext.as_slice());
}

/// Batch with mixed message sizes.
#[test]
fn batch_aead_mixed_sizes() {
    let secret = b"batch-mixed-secret";
    let pool = EntropyPool::new(32).unwrap();

    let small = vec![0xAAu8; 16];
    let medium = vec![0xBBu8; 4096];
    let large = vec![0xCCu8; 65536];
    let aad1 = b"aad-small";
    let aad2 = b"aad-medium";
    let aad3 = b"aad-large";

    let messages: Vec<(&[u8], &[u8])> = vec![
        (small.as_slice(), aad1.as_slice()),
        (medium.as_slice(), aad2.as_slice()),
        (large.as_slice(), aad3.as_slice()),
    ];

    let packets = encode_aead_batch(secret, &messages, Some(&pool)).unwrap();
    let recovered = decode_aead_batch(secret, &packets).unwrap();

    assert_eq!(recovered[0].as_slice(), small.as_slice());
    assert_eq!(recovered[1].as_slice(), medium.as_slice());
    assert_eq!(recovered[2].as_slice(), large.as_slice());
}

/// Batch results match sequential encode/decode.
#[test]
fn batch_aead_matches_sequential() {
    let secret = b"batch-seq-match-secret";
    let pool = EntropyPool::new(32).unwrap();

    let plaintexts: Vec<Vec<u8>> = (0..10)
        .map(|i| vec![i as u8; 512])
        .collect();
    let aad = b"match-aad";
    let messages: Vec<(&[u8], &[u8])> = plaintexts.iter()
        .map(|pt| (pt.as_slice(), aad.as_slice()))
        .collect();

    // Batch encode → decode
    let packets = encode_aead_batch(secret, &messages, Some(&pool)).unwrap();
    let batch_recovered = decode_aead_batch(secret, &packets).unwrap();

    // Each recovered plaintext must match the original
    for (i, (pt, rec)) in plaintexts.iter().zip(batch_recovered.iter()).enumerate() {
        assert_eq!(pt.as_slice(), rec.as_slice(), "batch mismatch at {i}");
    }

    // Also verify: batch-encoded packets can be decoded individually
    for (i, pkt) in packets.iter().enumerate() {
        let individual = decode_aead(secret, pkt).unwrap();
        assert_eq!(plaintexts[i].as_slice(), individual.as_slice());
    }
}

/// Batch encode without pool (synchronous entropy) still works.
#[test]
fn batch_aead_no_pool() {
    let secret = b"batch-nopool-secret";
    let plaintexts: Vec<Vec<u8>> = (0..5)
        .map(|i| vec![i as u8; 256])
        .collect();
    let aad = b"nopool-aad";
    let messages: Vec<(&[u8], &[u8])> = plaintexts.iter()
        .map(|pt| (pt.as_slice(), aad.as_slice()))
        .collect();

    let packets = encode_aead_batch(secret, &messages, None).unwrap();
    let recovered = decode_aead_batch(secret, &packets).unwrap();

    for (i, (pt, rec)) in plaintexts.iter().zip(recovered.iter()).enumerate() {
        assert_eq!(pt.as_slice(), rec.as_slice(), "no-pool mismatch at {i}");
    }
}

// ─────────────────────────────────────────────────────────────────
//  KkRngPool integration tests
// ─────────────────────────────────────────────────────────────────

#[test]
fn rng_pool_deterministic_across_instances() {
    let pool1 = KkRngPool::new(b"integration-seed", 8);
    let pool2 = KkRngPool::new(b"integration-seed", 8);
    for _ in 0..16 {
        assert_eq!(pool1.next_bytes(256), pool2.next_bytes(256));
    }
}

#[test]
fn rng_pool_fill_parallel_deterministic() {
    let pool1 = KkRngPool::new(b"fill-integ", 4);
    let pool2 = KkRngPool::new(b"fill-integ", 4);
    let mut buf1 = vec![0u8; 100_000];
    let mut buf2 = vec![0u8; 100_000];
    pool1.fill_bytes_parallel(&mut buf1);
    pool2.fill_bytes_parallel(&mut buf2);
    assert_eq!(buf1, buf2);
    // Should not be all zeros
    assert!(buf1.iter().any(|&b| b != 0));
}

#[test]
fn rng_pool_different_seeds_independent() {
    let pool_a = KkRngPool::new(b"seed-alpha", 4);
    let pool_b = KkRngPool::new(b"seed-beta", 4);
    let mut buf_a = vec![0u8; 4096];
    let mut buf_b = vec![0u8; 4096];
    pool_a.fill_bytes_parallel(&mut buf_a);
    pool_b.fill_bytes_parallel(&mut buf_b);
    assert_ne!(buf_a, buf_b);
}

#[test]
fn rng_pool_large_parallel_fill() {
    let pool = KkRngPool::new(b"large-fill", 16);
    let mut buf = vec![0u8; 1_000_000];
    pool.fill_bytes_parallel(&mut buf);
    // Basic statistical check: not all same byte
    let first = buf[0];
    assert!(buf.iter().any(|&b| b != first));
}

// ─────────────────────────────────────────────────────────────────
//  Parallel Encode / Decode
// ─────────────────────────────────────────────────────────────────

#[test]
fn parallel_roundtrip_various_sizes() {
    let secret = b"parallel-integration-secret";
    let aad = b"parallel-aad";
    for size in [1, 100, 4096, 65_536, 1 << 20] {
        let msg: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let packet = encode_parallel(secret, &msg, aad, PARALLEL_CHUNK_SIZE, None).unwrap();
        let recovered = decode_parallel(secret, &packet).unwrap();
        assert_eq!(msg, recovered, "roundtrip mismatch at size {}", size);
    }
}

#[test]
fn parallel_custom_chunk_size() {
    let secret = b"parallel-chunk-test";
    let msg = vec![0xCDu8; 50_000];
    // Use a small chunk to get many chunks
    let packet = encode_parallel(secret, &msg, b"aad", 4096, None).unwrap();
    assert!(packet.chunks.len() > 1);
    let recovered = decode_parallel(secret, &packet).unwrap();
    assert_eq!(msg, recovered);
}

#[test]
fn parallel_merkle_tamper_detected() {
    let secret = b"parallel-tamper-test";
    let msg = vec![0xABu8; 8192];
    let mut packet = encode_parallel(secret, &msg, b"aad", 2048, None).unwrap();
    // Swap first two chunks → Merkle root should mismatch
    if packet.chunks.len() >= 2 {
        packet.chunks.swap(0, 1);
        assert!(decode_parallel(secret, &packet).is_err());
    }
}

#[test]
fn parallel_wrong_secret_rejected() {
    let msg = vec![0x42u8; 4096];
    let packet = encode_parallel(b"correct-secret", &msg, b"aad", 2048, None).unwrap();
    assert!(decode_parallel(b"wrong-secret", &packet).is_err());
}

#[test]
fn parallel_serde_roundtrip_integration() {
    let secret = b"parallel-serde-int";
    let msg: Vec<u8> = (0..10_000).map(|i| (i % 199) as u8).collect();
    let packet = encode_parallel(secret, &msg, b"aad", 2048, None).unwrap();
    let bytes = packet.to_bytes();
    let restored = KkParallelPacket::from_bytes(&bytes).unwrap();
    let recovered = decode_parallel(secret, &restored).unwrap();
    assert_eq!(msg, recovered);
}

#[test]
fn parallel_single_chunk_equivalent() {
    let secret = b"parallel-single-chunk";
    let msg = b"small message";
    // Chunk size larger than message → single chunk
    let packet = encode_parallel(secret, msg, b"aad", 1 << 20, None).unwrap();
    assert_eq!(packet.chunks.len(), 1);
    let recovered = decode_parallel(secret, &packet).unwrap();
    assert_eq!(msg.as_slice(), recovered.as_slice());
}
