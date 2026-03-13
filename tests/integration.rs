// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

//! Integration tests for KK  - Keeney Kode
//!
//! These tests demonstrate and verify the core security properties
//! claimed by the KK primitive.

use kk_crypto::{decode, encode, KkPacket};
use kk_crypto::{encode_bound, decode_bound, KkBoundPacket, generate_challenge, GENESIS_MAC};
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
/// guarantee is in the entropy snapshot  - each encoding captures an
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
                "Entropy snapshots at T_{i} and T_{j} must differ  - each moment is unique"
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
    // Attacker tries various keys  - all must fail
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
/// Each encoding creates independent entropy  - knowing one packet
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
    // we expect high entropy  - many distinct byte values
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
        1,              // single byte  - scalar only
        4096,           // 1 full chunk  - scalar tail
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
