//! # KK  - Keeney Kode
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
//! No SHA-256, no HKDF, no HMAC  - 100% original KK.
//!
//! J.A. Keeney, Australia, 2026

pub mod codec;
pub mod entropy;
pub mod error;
pub mod kdf;
pub mod kk_mix;
pub mod qkd;
pub mod temporal;

// Re-export the primary API
pub use codec::{decode, encode, KkPacket};
pub use codec::{decode_split, encode_split, KkSealedMessage};
pub use entropy::EntropySnapshot;
pub use error::KkError;

// QKD re-exports
pub use qkd::{
    alice_prepare, bob_measure, distill_key, eve_intercept,
    encrypt_epsilon, decrypt_epsilon,
    Bb84Result, Basis, Qubit,
};
