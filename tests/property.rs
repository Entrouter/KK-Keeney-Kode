// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Property-based tests for KK-Crypto using proptest.

use proptest::prelude::*;
use std::time::Duration;

use kk_crypto::kk_mix::{kk_hash, kk_kdf, kk_mac};
use kk_crypto::{
    decode, decode_aead, decode_bound, decode_session, decode_session_aead, decode_split, encode,
    encode_aead, encode_bound, encode_session, encode_session_aead, encode_split,
    generate_challenge, RopeRatchet, GENESIS_MAC,
};

// ─────────────────────────────────────────────────────────────────
//  Strategies
// ─────────────────────────────────────────────────────────────────

fn secret() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64)
}

fn plaintext() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..512)
}

fn aad() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..128)
}

// ─────────────────────────────────────────────────────────────────
//  1. Roundtrip identity - all 4 codec modes
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn roundtrip_basic(ref key in secret(), ref msg in plaintext()) {
        let packet = encode(key, msg).unwrap();
        let recovered = decode(key, &packet).unwrap();
        prop_assert_eq!(&recovered, msg);
    }

    #[test]
    fn roundtrip_aead(ref key in secret(), ref msg in plaintext(), ref ad in aad()) {
        let packet = encode_aead(key, msg, ad).unwrap();
        prop_assert_eq!(&packet.aad, ad);
        let recovered = decode_aead(key, &packet).unwrap();
        prop_assert_eq!(&recovered, msg);
    }

    #[test]
    fn roundtrip_split(ref key in secret(), ref msg in plaintext()) {
        let (sealed, epsilon) = encode_split(key, msg).unwrap();
        let recovered = decode_split(key, &sealed, &epsilon).unwrap();
        prop_assert_eq!(&recovered, msg);
    }

    #[test]
    fn roundtrip_bound(ref key in secret(), ref msg in plaintext()) {
        let nonce = generate_challenge().unwrap();
        let packet = encode_bound(key, msg, &nonce, &GENESIS_MAC).unwrap();
        let recovered = decode_bound(key, &packet, &nonce, Duration::from_secs(60)).unwrap();
        prop_assert_eq!(&recovered, msg);
    }
}

// ─────────────────────────────────────────────────────────────────
//  2. Determinism - hash, KDF, MAC
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn hash_deterministic(ref data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let h1 = kk_hash(data);
        let h2 = kk_hash(data);
        prop_assert_eq!(h1, h2, "kk_hash must be deterministic");
    }

    #[test]
    fn kdf_deterministic(ref key in secret(), ref context in prop::collection::vec(any::<u8>(), 0..64)) {
        let k1 = kk_kdf(key, b"salt", context, 32);
        let k2 = kk_kdf(key, b"salt", context, 32);
        prop_assert_eq!(k1, k2, "kk_kdf must be deterministic");
    }

    #[test]
    fn mac_deterministic(ref key in secret(), ref data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let m1 = kk_mac(key, data);
        let m2 = kk_mac(key, data);
        prop_assert_eq!(m1, m2, "kk_mac must be deterministic");
    }
}

// ─────────────────────────────────────────────────────────────────
//  3. MAC forgery detection
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn mac_forgery_rejected(ref key in secret(), ref msg in plaintext()) {
        let packet = encode(key, msg).unwrap();

        // Flip a random bit in the ciphertext
        let mut tampered = packet.clone();
        if !tampered.ciphertext.is_empty() {
            tampered.ciphertext[0] ^= 0x01;
        }

        let result = decode(key, &tampered);
        prop_assert!(result.is_err(), "Tampered ciphertext must be rejected");
    }

    #[test]
    fn aead_aad_forgery_rejected(ref key in secret(), ref msg in plaintext(), ref ad in aad()) {
        let packet = encode_aead(key, msg, ad).unwrap();

        // Tamper with the AAD
        let mut tampered = packet.clone();
        tampered.aad.push(0xFF);

        let result = decode_aead(key, &tampered);
        prop_assert!(result.is_err(), "Tampered AAD must be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────
//  4. Key sensitivity
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn wrong_key_rejected(ref key in secret(), ref msg in plaintext()) {
        let packet = encode(key, msg).unwrap();

        // Derive a wrong key by flipping a bit
        let mut wrong_key = key.clone();
        wrong_key[0] ^= 0x01;

        let result = decode(&wrong_key, &packet);
        prop_assert!(result.is_err(), "Wrong key must be rejected");
    }

    #[test]
    fn hash_key_sensitivity(ref data in prop::collection::vec(any::<u8>(), 1..256)) {
        let mut altered = data.clone();
        altered[0] ^= 0x01;

        let h1 = kk_hash(data);
        let h2 = kk_hash(&altered);
        prop_assert_ne!(h1, h2, "Single bit flip must change hash");
    }
}

// ─────────────────────────────────────────────────────────────────
//  5. Length preservation
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn ciphertext_length_equals_plaintext(ref key in secret(), ref msg in plaintext()) {
        let packet = encode(key, msg).unwrap();
        prop_assert_eq!(
            packet.ciphertext.len(), msg.len(),
            "Ciphertext length must equal plaintext length (XOR stream cipher)"
        );
    }

    #[test]
    fn aead_ciphertext_length(ref key in secret(), ref msg in plaintext(), ref ad in aad()) {
        let packet = encode_aead(key, msg, ad).unwrap();
        prop_assert_eq!(
            packet.ciphertext.len(), msg.len(),
            "AEAD ciphertext length must equal plaintext length"
        );
    }
}

// ─────────────────────────────────────────────────────────────────
//  6. Session ratchet ordering
// ─────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn session_roundtrip_sequence(
        ref key in secret(),
        ref msgs in prop::collection::vec(plaintext(), 1..5)
    ) {
        let context = b"proptest-session";
        let mut sender = RopeRatchet::new(key, context).unwrap();
        let mut receiver = RopeRatchet::new(key, context).unwrap();

        for msg in msgs {
            let packet = encode_session(&mut sender, msg).unwrap();
            let recovered = decode_session(&mut receiver, &packet).unwrap();
            prop_assert_eq!(&recovered, msg);
        }
    }

    #[test]
    fn session_aead_roundtrip_sequence(
        ref key in secret(),
        ref msgs in prop::collection::vec(plaintext(), 1..5),
        ref ad in aad(),
    ) {
        let context = b"proptest-aead-session";
        let mut sender = RopeRatchet::new(key, context).unwrap();
        let mut receiver = RopeRatchet::new(key, context).unwrap();

        for msg in msgs {
            let packet = encode_session_aead(&mut sender, msg, ad).unwrap();
            let recovered = decode_session_aead(&mut receiver, &packet).unwrap();
            prop_assert_eq!(&recovered, msg);
        }
    }

    #[test]
    fn session_counter_advances(
        ref key in secret(),
        ref msgs in prop::collection::vec(plaintext(), 2..6)
    ) {
        let context = b"proptest-counter";
        let mut sender = RopeRatchet::new(key, context).unwrap();
        let mut receiver = RopeRatchet::new(key, context).unwrap();

        let mut prev_counter = sender.counter();
        for msg in msgs {
            let packet = encode_session(&mut sender, msg).unwrap();
            prop_assert!(sender.counter() > prev_counter, "Counter must strictly increase");
            prev_counter = sender.counter();
            let _ = decode_session(&mut receiver, &packet).unwrap();
        }
    }
}

// ─────────────────────────────────────────────────────────────────
//  7. Temporal commit → verify
// ─────────────────────────────────────────────────────────────────

proptest! {
    #[test]
    fn temporal_bound_roundtrip(ref key in secret(), ref msg in plaintext()) {
        let nonce = generate_challenge().unwrap();
        let packet = encode_bound(key, msg, &nonce, &GENESIS_MAC).unwrap();

        // Verify with correct nonce succeeds
        let result = decode_bound(key, &packet, &nonce, Duration::from_secs(60));
        prop_assert!(result.is_ok(), "Correct nonce + fresh packet must verify");
    }

    #[test]
    fn temporal_wrong_nonce_rejected(ref key in secret(), ref msg in plaintext()) {
        let nonce = generate_challenge().unwrap();
        let packet = encode_bound(key, msg, &nonce, &GENESIS_MAC).unwrap();

        // Wrong nonce must fail
        let wrong_nonce = generate_challenge().unwrap();
        let result = decode_bound(key, &packet, &wrong_nonce, Duration::from_secs(60));
        prop_assert!(result.is_err(), "Wrong nonce must be rejected");
    }
}
