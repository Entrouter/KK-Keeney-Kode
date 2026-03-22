// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! # KK, Keeney Kode
//!
//! A novel cryptographic primitive where symbol values are temporal
//! functions of universal entropy.
//!
//! ## Core Principle
//!
//! In all existing cryptography, symbol 'A' has a fixed value and encryption
//! hides what 'A' means. In KK, symbol 'A' has no fixed value:
//!
//! ```text
//! KK(S) = S^ε  where ε = universal entropy at moment of creation
//! ```
//!
//! The symbol's fundamental value is a function of the universe
//! at the instant it was born. The same symbol encoded twice produces
//! two cryptographically unrelated values.
//!
//! ## Quick Start
//!
//! ```rust
//! use kk_crypto::{encode, decode};
//!
//! // Both parties share a secret
//! let shared_secret = b"our-shared-secret";
//!
//! // Encode: symbol values become functions of this cosmic instant
//! let packet = encode(shared_secret, b"Hello KK!").unwrap();
//!
//! // Transmit packet.to_bytes() to receiver...
//!
//! // Decode: same secret, same moment reference, same values
//! let plaintext = decode(shared_secret, &packet).unwrap();
//! assert_eq!(plaintext, b"Hello KK!");
//! ```
//!
//! ## Architecture
//!
//! ```text
//! Entropy Sources → KK-Mix → Per-Symbol Derivation → Temporal Binding → Encoding
//!     (entropy.rs)  (kk_mix.rs)    (kdf.rs)            (temporal.rs)     (codec.rs)
//! ```
//!
//! Every cryptographic operation is built from a single novel primitive:
//! the KK permutation (Multiply-Fold-Rotate sponge construction).
//! No SHA-256, no HKDF, no HMAC, 100% original KK.
//!
//! ## Security Model
//!
//! **Threat model:** KK assumes a pre-shared secret between sender and
//! receiver. An attacker may observe, replay, or modify ciphertext in
//! transit but does not know the shared secret.
//!
//! **Confidentiality:** Each encoding captures a unique `EntropySnapshot`
//! (CPU counters, thread jitter, OS randomness). The snapshot feeds the
//! KK-KDF to derive per-chunk keystream, ensuring the same plaintext
//! never produces the same ciphertext twice.
//!
//! **Integrity:** Every `KkPacket` carries a KK-MAC tag over
//! (ciphertext ‖ entropy snapshot). `decode` rejects any packet whose
//! tag does not verify, preventing silent tampering.
//!
//! **Temporal binding:** The `TemporalCommitment` in each packet commits
//! to the entropy used during encoding. The receiver re-derives the
//! commitment from the embedded snapshot and the shared secret, rejecting
//! packets if the commitment does not match.
//!
//! **Key hygiene:** Intermediate keys (commit keys, chunk keystream) are
//! zeroized via the `zeroize` crate immediately after use. The output
//! buffer is zeroized on error paths to prevent partial plaintext leaks.
//!
//! **Limitations:**
//! - KK is a novel, un-audited primitive, it has **not** been reviewed
//!   by third-party cryptographers. Do not use for production security.
//! - The base codec has no forward secrecy. Use the `session` module's
//!   Rope Ratchet (`encode_session`/`decode_session`) for ~192-bit
//!   forward secrecy via 4-strand ratcheting.
//! - Replay protection is **not** built in; callers must add sequence
//!   numbers or timestamps at the protocol layer.
//!
//! J.A. Keeney, Australia, 2026

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
pub mod codec;
#[cfg(feature = "std")]
pub mod eka;
#[cfg(feature = "std")]
pub mod entropy;
#[cfg(feature = "std")]
pub mod entropy_pool;
pub mod error;
#[cfg(feature = "std")]
pub mod kdf;
pub mod kk_mix;
#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(feature = "cuda")]
pub mod cuda;
#[cfg(all(target_arch = "x86_64", feature = "std"))]
pub(crate) mod kk_mix_avx512;
#[cfg(feature = "std")]
pub mod qkd;
pub mod rng;
#[cfg(feature = "std")]
pub mod session;
#[cfg(feature = "std")]
pub mod temporal;

// Re-export the primary API
#[cfg(feature = "std")]
pub use codec::{decode, encode, KkPacket};
#[cfg(feature = "std")]
pub use codec::{decode_split, encode_split, KkSealedMessage};
#[cfg(feature = "std")]
pub use codec::{decode_bound, encode_bound, KkBoundPacket};
#[cfg(feature = "std")]
pub use codec::{decode_aead, encode_aead, KkAeadPacket};
#[cfg(feature = "std")]
pub use codec::{StreamEncoder, StreamDecoder};
#[cfg(feature = "std")]
#[doc(hidden)]
pub use codec::{encode_with_snapshot, encode_aead_with_snapshot};
#[cfg(feature = "std")]
pub use entropy::EntropySnapshot;
#[cfg(feature = "std")]
pub use entropy_pool::EntropyPool;
#[cfg(feature = "std")]
pub use codec::{encode_pooled, encode_aead_pooled};
#[cfg(feature = "std")]
pub use codec::{encode_aead_batch, decode_aead_batch};
#[cfg(feature = "std")]
pub use codec::{encode_parallel, decode_parallel, KkParallelPacket, PARALLEL_CHUNK_SIZE};
pub use error::KkError;
#[cfg(feature = "std")]
pub use temporal::{generate_challenge, TemporalProof, GENESIS_MAC};

// Session (forward secrecy) re-exports
#[cfg(feature = "std")]
pub use session::{encode_session, decode_session, RopeRatchet, RopeStep, RopePacket};
#[cfg(feature = "std")]
pub use session::{encode_session_aead, decode_session_aead, RopeAeadPacket};

// QKD re-exports
#[cfg(feature = "std")]
pub use qkd::{
    alice_prepare, bob_measure, distill_key, eve_intercept,
    encrypt_epsilon, decrypt_epsilon,
    Bb84Result, Basis, Qubit,
};

// EKA (Entropy Key Agreement) re-exports
#[cfg(feature = "std")]
pub use eka::{EkaInitiator, EkaResponder, EkaMsg1, EkaMsg2, EkaMsg3};

// RNG re-exports
pub use rng::KkRng;
#[cfg(feature = "std")]
pub use rng::KkRngPool;
