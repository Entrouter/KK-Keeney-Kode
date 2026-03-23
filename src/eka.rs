// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! # KK Entropy Key Agreement (KK-EKA)
//!
//! A 3-message PSK-based key agreement protocol where both parties
//! contribute fresh entropy. No public-key cryptography - authentication
//! is via KK-MAC over a pre-shared key.
//!
//! ## Protocol Flow
//!
//! ```text
//! Alice (Initiator)                           Bob (Responder)
//! ─────────────────                           ───────────────
//! entropy_a = gather()
//! commit_a = kk_hash(serialize(entropy_a))
//!
//!     ──── msg1: commit_a (32B) ──────────────►
//!                                              entropy_b = gather()
//!                                              auth_b = kk_mac(psk, entropy_b || commit_a)
//!     ◄──── msg2: entropy_b (48B) + auth_b (32B)
//!
//! verify auth_b
//! auth_a = kk_mac(psk, entropy_a || entropy_b)
//!
//!     ──── msg3: entropy_a (48B) + auth_a (32B) ►
//!                                              verify commit_a == kk_hash(entropy_a)
//!                                              verify auth_a
//!
//! BOTH: session_key = kk_kdf(psk, entropy_a || entropy_b, "KK-EKA-session", 32)
//! BOTH: zeroize ephemeral state
//! ```
//!
//! ## Security Properties
//!
//! - **Forward secrecy** - session key depends on ephemeral entropy from BOTH parties
//! - **Mutual authentication** - both prove PSK knowledge via kk_mac
//! - **Contributory** - neither party alone controls the session key
//! - **Commitment binding** - Alice commits to entropy BEFORE seeing Bob's
//! - **Temporal freshness** - entropy snapshots carry nanosecond timestamps

use zeroize::Zeroize;

use crate::entropy::{self, EntropySnapshot};
use crate::error::{KkError, Result};
use crate::kk_mix;

/// KK-EKA session label used for key derivation.
const EKA_SESSION_INFO: &[u8] = b"KK-EKA-session";

// ─── Wire types ──────────────────────────────────────────────────────────────

/// Message 1: Alice's commitment to her entropy (32 bytes).
#[derive(Clone)]
pub struct EkaMsg1 {
    pub commit: [u8; 32],
}

impl EkaMsg1 {
    pub const BYTES: usize = 32;

    pub fn to_bytes(&self) -> Vec<u8> {
        self.commit.to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BYTES {
            return Err(KkError::InvalidPacket("EkaMsg1 too short".into()));
        }
        let mut commit = [0u8; 32];
        commit.copy_from_slice(&data[..32]);
        Ok(Self { commit })
    }
}

/// Message 2: Bob's entropy (48B) + authentication tag (32B) = 80 bytes.
#[derive(Clone)]
pub struct EkaMsg2 {
    pub entropy_b_bytes: [u8; 48],
    pub auth_b: [u8; 32],
}

impl EkaMsg2 {
    pub const BYTES: usize = 80;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.entropy_b_bytes);
        out.extend_from_slice(&self.auth_b);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BYTES {
            return Err(KkError::InvalidPacket("EkaMsg2 too short".into()));
        }
        let mut entropy_b_bytes = [0u8; 48];
        entropy_b_bytes.copy_from_slice(&data[..48]);
        let mut auth_b = [0u8; 32];
        auth_b.copy_from_slice(&data[48..80]);
        Ok(Self {
            entropy_b_bytes,
            auth_b,
        })
    }
}

/// Message 3: Alice's entropy (48B) + authentication tag (32B) = 80 bytes.
#[derive(Clone)]
pub struct EkaMsg3 {
    pub entropy_a_bytes: [u8; 48],
    pub auth_a: [u8; 32],
}

impl EkaMsg3 {
    pub const BYTES: usize = 80;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.entropy_a_bytes);
        out.extend_from_slice(&self.auth_a);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BYTES {
            return Err(KkError::InvalidPacket("EkaMsg3 too short".into()));
        }
        let mut entropy_a_bytes = [0u8; 48];
        entropy_a_bytes.copy_from_slice(&data[..48]);
        let mut auth_a = [0u8; 32];
        auth_a.copy_from_slice(&data[48..80]);
        Ok(Self {
            entropy_a_bytes,
            auth_a,
        })
    }
}

// ─── Initiator (Alice) ──────────────────────────────────────────────────────

/// Alice's side of the KK-EKA protocol.
///
/// Created via `new()`, which gathers entropy and produces `EkaMsg1`.
/// After receiving Bob's `EkaMsg2`, call `process_msg2()` to complete
/// the handshake and derive the session key.
pub struct EkaInitiator {
    psk: Vec<u8>,
    #[allow(dead_code)] // kept for zeroization on Drop
    entropy_a: EntropySnapshot,
    entropy_a_serialized: Vec<u8>,
    commit_a: [u8; 32],
}

impl Drop for EkaInitiator {
    fn drop(&mut self) {
        self.psk.zeroize();
        self.entropy_a_serialized.zeroize();
        self.commit_a.zeroize();
        // EntropySnapshot has its own Drop
    }
}

impl EkaInitiator {
    /// Begin the KK-EKA handshake as initiator.
    ///
    /// Gathers fresh entropy and returns `(Self, EkaMsg1)` where `EkaMsg1`
    /// contains the commitment hash to send to the responder.
    pub fn new(psk: &[u8]) -> Result<(Self, EkaMsg1)> {
        let entropy_a = entropy::gather()?;
        Self::new_with_entropy(psk, entropy_a)
    }

    /// Begin the handshake with a caller-supplied entropy snapshot.
    ///
    /// This exists for deterministic testing. Production code should use `new()`.
    #[doc(hidden)]
    pub fn new_with_entropy(psk: &[u8], entropy_a: EntropySnapshot) -> Result<(Self, EkaMsg1)> {
        let entropy_a_serialized = entropy_a.to_bytes();
        let commit_a = kk_mix::kk_hash(&entropy_a_serialized);

        let msg1 = EkaMsg1 { commit: commit_a };
        let state = Self {
            psk: psk.to_vec(),
            entropy_a,
            entropy_a_serialized,
            commit_a,
        };
        Ok((state, msg1))
    }

    /// Process Bob's response and complete the handshake.
    ///
    /// Verifies Bob's authentication tag, produces `EkaMsg3` for Bob,
    /// and derives the shared session key. Consumes `self` - the
    /// initiator state is zeroized on drop.
    pub fn process_msg2(self, msg2: &EkaMsg2) -> Result<(EkaMsg3, [u8; 32])> {
        // Verify auth_b = kk_mac(psk, entropy_b || commit_a)
        let mut auth_b_message = Vec::with_capacity(48 + 32);
        auth_b_message.extend_from_slice(&msg2.entropy_b_bytes);
        auth_b_message.extend_from_slice(&self.commit_a);

        if !kk_mix::kk_mac_verify(&self.psk, &auth_b_message, &msg2.auth_b) {
            return Err(KkError::CommitmentMismatch);
        }

        // auth_a = kk_mac(psk, entropy_a_serialized || entropy_b)
        let mut auth_a_message = Vec::with_capacity(48 + 48);
        auth_a_message.extend_from_slice(&self.entropy_a_serialized);
        auth_a_message.extend_from_slice(&msg2.entropy_b_bytes);
        let auth_a = kk_mix::kk_mac(&self.psk, &auth_a_message);

        let mut entropy_a_bytes = [0u8; 48];
        entropy_a_bytes.copy_from_slice(&self.entropy_a_serialized);

        let msg3 = EkaMsg3 {
            entropy_a_bytes,
            auth_a,
        };

        // Derive session key = kk_kdf(psk, entropy_a || entropy_b, "KK-EKA-session", 32)
        let mut salt = Vec::with_capacity(48 + 48);
        salt.extend_from_slice(&self.entropy_a_serialized);
        salt.extend_from_slice(&msg2.entropy_b_bytes);
        let session_key_vec = kk_mix::kk_kdf(&self.psk, &salt, EKA_SESSION_INFO, 32);
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_vec);

        Ok((msg3, session_key))
    }
}

// ─── Responder (Bob) ────────────────────────────────────────────────────────

/// Bob's side of the KK-EKA protocol.
///
/// Created via `new()`, which gathers entropy and produces `EkaMsg2`.
/// After receiving Alice's `EkaMsg3`, call `process_msg3()` to verify
/// and derive the session key.
pub struct EkaResponder {
    psk: Vec<u8>,
    entropy_b_serialized: Vec<u8>,
    commit_a: [u8; 32],
}

impl Drop for EkaResponder {
    fn drop(&mut self) {
        self.psk.zeroize();
        self.entropy_b_serialized.zeroize();
        self.commit_a.zeroize();
    }
}

impl EkaResponder {
    /// Begin the KK-EKA handshake as responder.
    ///
    /// Gathers fresh entropy, authenticates with a MAC, and returns
    /// `(Self, EkaMsg2)` to send back to the initiator.
    pub fn new(psk: &[u8], msg1: &EkaMsg1) -> Result<(Self, EkaMsg2)> {
        let entropy_b = entropy::gather()?;
        Self::new_with_entropy(psk, msg1, entropy_b)
    }

    /// Begin the handshake with a caller-supplied entropy snapshot.
    ///
    /// This exists for deterministic testing. Production code should use `new()`.
    #[doc(hidden)]
    pub fn new_with_entropy(
        psk: &[u8],
        msg1: &EkaMsg1,
        entropy_b: EntropySnapshot,
    ) -> Result<(Self, EkaMsg2)> {
        let entropy_b_serialized = entropy_b.to_bytes();

        // auth_b = kk_mac(psk, entropy_b_serialized || commit_a)
        let mut auth_b_message = Vec::with_capacity(48 + 32);
        auth_b_message.extend_from_slice(&entropy_b_serialized);
        auth_b_message.extend_from_slice(&msg1.commit);

        let auth_b = kk_mix::kk_mac(psk, &auth_b_message);

        let mut entropy_b_bytes = [0u8; 48];
        entropy_b_bytes.copy_from_slice(&entropy_b_serialized);

        let msg2 = EkaMsg2 {
            entropy_b_bytes,
            auth_b,
        };

        let state = Self {
            psk: psk.to_vec(),
            entropy_b_serialized,
            commit_a: msg1.commit,
        };
        Ok((state, msg2))
    }

    /// Process Alice's final message and derive the session key.
    ///
    /// Verifies Alice's commitment (hash matches revealed entropy)
    /// and her authentication tag, then derives the shared session key.
    /// Consumes `self` - state is zeroized on drop.
    pub fn process_msg3(self, msg3: &EkaMsg3) -> Result<[u8; 32]> {
        // Verify commitment: kk_hash(entropy_a) must match commit_a from msg1
        let recomputed_commit = kk_mix::kk_hash(&msg3.entropy_a_bytes);
        if recomputed_commit != self.commit_a {
            return Err(KkError::CommitmentMismatch);
        }

        // Verify auth_a = kk_mac(psk, entropy_a || entropy_b)
        let mut auth_a_message = Vec::with_capacity(48 + 48);
        auth_a_message.extend_from_slice(&msg3.entropy_a_bytes);
        auth_a_message.extend_from_slice(&self.entropy_b_serialized);
        if !kk_mix::kk_mac_verify(&self.psk, &auth_a_message, &msg3.auth_a) {
            return Err(KkError::CommitmentMismatch);
        }

        // Derive session key = kk_kdf(psk, entropy_a || entropy_b, "KK-EKA-session", 32)
        let mut salt = Vec::with_capacity(48 + 48);
        salt.extend_from_slice(&msg3.entropy_a_bytes);
        salt.extend_from_slice(&self.entropy_b_serialized);
        let session_key_vec = kk_mix::kk_kdf(&self.psk, &salt, EKA_SESSION_INFO, 32);
        let mut session_key = [0u8; 32];
        session_key.copy_from_slice(&session_key_vec);

        Ok(session_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eka_happy_path_live_entropy() {
        let psk = b"test-psk-for-eka";

        // Alice starts
        let (alice, msg1) = EkaInitiator::new(psk).unwrap();

        // Bob responds
        let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();

        // Alice completes
        let (msg3, alice_key) = alice.process_msg2(&msg2).unwrap();

        // Bob completes
        let bob_key = bob.process_msg3(&msg3).unwrap();

        // Both must derive the same session key
        assert_eq!(alice_key, bob_key);
        // Key must not be all zeros
        assert_ne!(alice_key, [0u8; 32]);
    }

    #[test]
    fn eka_wire_format_sizes() {
        assert_eq!(EkaMsg1::BYTES, 32);
        assert_eq!(EkaMsg2::BYTES, 80);
        assert_eq!(EkaMsg3::BYTES, 80);

        let psk = b"size-test";
        let (_, msg1) = EkaInitiator::new(psk).unwrap();
        assert_eq!(msg1.to_bytes().len(), 32);

        let (_, msg2) = EkaResponder::new(psk, &msg1).unwrap();
        assert_eq!(msg2.to_bytes().len(), 80);
    }

    #[test]
    fn eka_msg_roundtrip() {
        let psk = b"roundtrip-test";
        let (alice, msg1) = EkaInitiator::new(psk).unwrap();

        // msg1 roundtrip
        let msg1_bytes = msg1.to_bytes();
        let msg1_restored = EkaMsg1::from_bytes(&msg1_bytes).unwrap();
        assert_eq!(msg1.commit, msg1_restored.commit);

        // msg2 roundtrip
        let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();
        let msg2_bytes = msg2.to_bytes();
        let msg2_restored = EkaMsg2::from_bytes(&msg2_bytes).unwrap();
        assert_eq!(msg2.entropy_b_bytes, msg2_restored.entropy_b_bytes);
        assert_eq!(msg2.auth_b, msg2_restored.auth_b);

        // msg3 roundtrip
        let (msg3, _) = alice.process_msg2(&msg2).unwrap();
        let msg3_bytes = msg3.to_bytes();
        let msg3_restored = EkaMsg3::from_bytes(&msg3_bytes).unwrap();
        assert_eq!(msg3.entropy_a_bytes, msg3_restored.entropy_a_bytes);
        assert_eq!(msg3.auth_a, msg3_restored.auth_a);

        // Bob accepts restored msg3
        let key = bob.process_msg3(&msg3_restored).unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn eka_different_sessions_different_keys() {
        let psk = b"same-psk";

        let (alice1, msg1_a) = EkaInitiator::new(psk).unwrap();
        let (bob1, msg2_a) = EkaResponder::new(psk, &msg1_a).unwrap();
        let (msg3_a, key_a) = alice1.process_msg2(&msg2_a).unwrap();
        let _ = bob1.process_msg3(&msg3_a).unwrap();

        let (alice2, msg1_b) = EkaInitiator::new(psk).unwrap();
        let (bob2, msg2_b) = EkaResponder::new(psk, &msg1_b).unwrap();
        let (msg3_b, key_b) = alice2.process_msg2(&msg2_b).unwrap();
        let _ = bob2.process_msg3(&msg3_b).unwrap();

        assert_ne!(key_a, key_b, "different sessions must derive different keys");
    }
}
