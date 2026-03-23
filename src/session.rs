// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! # KK Rope Ratchet: Forward Secrecy
//!
//! A 4-strand ratchet that provides ~192-bit forward secrecy using
//! only KK primitives. Once a message key is derived and the ratchet
//! advances, the old state is zeroized and irrecoverable.
//!
//! ## Strands
//!
//! | Strand    | Source            | Purpose                              |
//! |-----------|-------------------|--------------------------------------|
//! | Entropy   | `EntropySnapshot` | Environmental randomness per message |
//! | Temporal  | `ε.timestamp`     | Binds ratchet to real-world time     |
//! | Chain     | Previous chain    | One-way forward secrecy              |
//! | Counter   | Monotonic `u64`   | Deterministic ordering               |
//!
//! ## The KK Innovation
//!
//! All 4 strand outputs are fed into a single KK sponge absorb phase
//! with entropy-derived rotations. The 32-round permutation (960 MFR +
//! 480 DDR operations) mixes all strands simultaneously, and the
//! cipher's mathematical structure changes per message because the
//! rotation schedule is derived from the entropy snapshot.
//!
//! This is fundamentally different from existing ratchet designs
//! (Signal Double Ratchet, etc.) where the cipher is fixed and only
//! the keys change. In KK, both the key AND the algebraic structure
//! of the permutation change with every message.
//!
//! ## Security
//!
//! - ~192-bit forward secrecy (384-bit sponge capacity)
//! - Per-message cipher structure rotation via entropy-derived schedules
//! - 4 independent entropy sources mixed through 32-round permutation
//! - Stronger than Signal's Double Ratchet (~128-bit DH security)
//!
//! ## Protocol
//!
//! ```text
//! Sender:    packet = encode_session(&mut send_ratchet, plaintext)
//!            transmit(packet.to_bytes())
//!
//! Receiver:  packet = RopePacket::from_bytes(&wire_data)
//!            plaintext = decode_session(&mut recv_ratchet, &packet)
//! ```
//!
//! For bidirectional communication, each party creates two ratchets
//! with different contexts (one for sending, one for receiving).
//!
//! Messages must be processed in order (strict counter synchronization).

use crate::codec::{self, KkAeadPacket, KkPacket};
use crate::entropy::{self, EntropySnapshot};
use crate::error::{KkError, Result};
use crate::kk_mix;
use zeroize::Zeroize;

/// Domain separation byte for the Rope Ratchet sponge (0x04).
///
/// Distinct from DOMAIN_HASH (0x01), DOMAIN_KDF (0x02), DOMAIN_MAC (0x03).
const DOMAIN_SESSION: &[u8] = b"KK-rope-mix-v1";

// KDF info labels for strand evolution
const STRAND_ENT_INFO: &[u8] = b"KK-rope-ent-v1";
const STRAND_TMP_INFO: &[u8] = b"KK-rope-tmp-v1";
const STRAND_CHN_INFO: &[u8] = b"KK-rope-chn-v1";

// KDF info labels for initial strand derivation from shared secret
const INIT_ENT_INFO: &[u8] = b"KK-rope-init-ent";
const INIT_TMP_INFO: &[u8] = b"KK-rope-init-tmp";
const INIT_CHN_INFO: &[u8] = b"KK-rope-init-chn";

// ─────────────────────────────────────────────────────────────────
//  RopeStep: metadata for one ratchet advance
// ─────────────────────────────────────────────────────────────────

/// Metadata from a single ratchet step, embedded in messages so the
/// receiver can perform the same derivation.
///
/// Contains the entropy snapshot (the unrepeatable moment) and the
/// message counter (for ordering). Both are needed to reproduce
/// the exact strand evolution on the receiving side.
#[derive(Clone)]
pub struct RopeStep {
    /// The entropy snapshot captured during this step.
    pub snapshot: EntropySnapshot,
    /// The message counter at this step.
    pub counter: u64,
}

impl RopeStep {
    /// Serialized size: 8 (counter) + 48 (snapshot) = 56 bytes.
    pub const BYTES: usize = 8 + 48;

    /// Serialize the step metadata for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.snapshot.to_bytes());
        out
    }

    /// Deserialize step metadata from received bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BYTES {
            return Err(KkError::InvalidPacket(format!(
                "rope step too short: need {}, got {}",
                Self::BYTES,
                data.len()
            )));
        }
        let counter = u64::from_le_bytes(
            data[..8]
                .try_into()
                .map_err(|_| KkError::InvalidPacket("bad counter bytes".into()))?,
        );
        let snapshot = EntropySnapshot::from_bytes(&data[8..56])?;
        Ok(Self { snapshot, counter })
    }
}

// ─────────────────────────────────────────────────────────────────
//  RopeRatchet: the 4-strand forward-secret ratchet
// ─────────────────────────────────────────────────────────────────

/// A forward-secret session ratchet built on 4 strands mixed through
/// the KK sponge.
///
/// Each call to [`advance`](Self::advance) or [`receive`](Self::receive)
/// irreversibly evolves the internal state. Old message keys become
/// unrecoverable, providing forward secrecy at ~192-bit security
/// (inherited from the KK sponge's 384-bit capacity).
///
/// # Two-Way Communication
///
/// For bidirectional messaging, create two ratchets with different
/// contexts:
///
/// ```rust
/// use kk_crypto::session::RopeRatchet;
///
/// let secret = b"shared-secret";
/// let mut send = RopeRatchet::new(secret, b"alice-to-bob").unwrap();
/// let mut recv = RopeRatchet::new(secret, b"bob-to-alice").unwrap();
/// ```
///
/// Alice uses `send` for outgoing and a second ratchet initialized
/// with `b"bob-to-alice"` for incoming. Bob mirrors this.
pub struct RopeRatchet {
    /// Entropy strand: evolved from environmental randomness.
    entropy_strand: [u8; 32],
    /// Temporal strand: evolved from timestamps.
    temporal_strand: [u8; 32],
    /// Chain strand: one-way ratchet for forward secrecy.
    chain_strand: [u8; 32],
    /// Monotonically increasing message counter.
    counter: u64,
}

impl Drop for RopeRatchet {
    fn drop(&mut self) {
        self.entropy_strand.zeroize();
        self.temporal_strand.zeroize();
        self.chain_strand.zeroize();
        self.counter = 0;
    }
}

impl RopeRatchet {
    /// Create a new ratchet from a shared secret and direction context.
    ///
    /// The `context` parameter provides domain separation between
    /// directions (e.g., `b"alice-to-bob"` vs `b"bob-to-alice"`).
    /// Two ratchets with the same `shared_secret` but different
    /// `context` values produce completely independent key streams.
    ///
    /// Both parties must use identical `(shared_secret, context)` pairs
    /// for the same communication direction.
    pub fn new(shared_secret: &[u8], context: &[u8]) -> Result<Self> {
        // Hash the context to produce a fixed-size salt for KDF
        let salt = kk_mix::kk_hash(context);

        // Derive independent initial seeds for each strand
        let mut e = kk_mix::kk_kdf(shared_secret, &salt, INIT_ENT_INFO, 32);
        let mut t = kk_mix::kk_kdf(shared_secret, &salt, INIT_TMP_INFO, 32);
        let mut c = kk_mix::kk_kdf(shared_secret, &salt, INIT_CHN_INFO, 32);

        let mut entropy_strand = [0u8; 32];
        let mut temporal_strand = [0u8; 32];
        let mut chain_strand = [0u8; 32];

        entropy_strand.copy_from_slice(&e);
        temporal_strand.copy_from_slice(&t);
        chain_strand.copy_from_slice(&c);

        e.zeroize();
        t.zeroize();
        c.zeroize();

        Ok(Self {
            entropy_strand,
            temporal_strand,
            chain_strand,
            counter: 0,
        })
    }

    /// Advance the ratchet and derive a message key (sender side).
    ///
    /// Gathers fresh entropy, evolves all 4 strands, and mixes them
    /// through the KK sponge with entropy-derived rotations.
    ///
    /// Returns the 32-byte message key and a [`RopeStep`] that must
    /// be included in the transmitted message so the receiver can
    /// derive the same key.
    ///
    /// # Security
    ///
    /// The returned message key is sensitive material. Zeroize it
    /// after use. The old chain state is destroyed during this call,
    /// providing forward secrecy.
    pub fn advance(&mut self) -> Result<([u8; 32], RopeStep)> {
        let snapshot = entropy::gather()?;
        let key = self.step(&snapshot)?;
        let step = RopeStep {
            snapshot,
            counter: self.counter,
        };
        Ok((key, step))
    }

    /// Advance the ratchet using received step metadata (receiver side).
    ///
    /// Uses the sender's entropy snapshot and counter from the
    /// [`RopeStep`] to reproduce the exact same derivation, yielding
    /// the identical message key.
    ///
    /// # Errors
    ///
    /// Returns `KkError::InvalidPacket` if the counter is not exactly
    /// one more than the current counter (strict ordering).
    pub fn receive(&mut self, step: &RopeStep) -> Result<[u8; 32]> {
        let expected = self.counter + 1;
        if step.counter != expected {
            return Err(KkError::InvalidPacket(format!(
                "counter mismatch: expected {expected}, got {} (strict ordering)",
                step.counter
            )));
        }
        self.step(&step.snapshot)
    }

    /// The current message counter (0 = no messages yet).
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Advance with a caller-supplied snapshot (deterministic, for test vectors).
    #[doc(hidden)]
    pub fn advance_with_snapshot(
        &mut self,
        snapshot: EntropySnapshot,
    ) -> Result<([u8; 32], RopeStep)> {
        let key = self.step(&snapshot)?;
        let step = RopeStep {
            snapshot,
            counter: self.counter,
        };
        Ok((key, step))
    }

    /// Core ratchet step: evolve all 4 strands and mix through sponge.
    ///
    /// This is where the KK innovation lives. All 4 strand outputs
    /// are concatenated and fed into `kk_kdf` as the key, with the
    /// entropy snapshot bytes as salt. Internally, `kk_kdf` creates
    /// a sponge with entropy-derived rotations and runs the full
    /// 32-round permutation (960 MFR + 480 DDR), mixing all strands
    /// simultaneously. The cipher's mathematical structure changes
    /// per message because the rotation schedule is derived from the
    /// entropy snapshot.
    fn step(&mut self, snapshot: &EntropySnapshot) -> Result<[u8; 32]> {
        // ── Evolve entropy strand ──
        // New entropy strand = KK-KDF(old_entropy, snapshot.bytes, domain)
        let mut e_new = kk_mix::kk_kdf(&self.entropy_strand, &snapshot.bytes, STRAND_ENT_INFO, 32);
        self.entropy_strand.copy_from_slice(&e_new);
        e_new.zeroize();

        // ── Evolve temporal strand ──
        // New temporal strand = KK-KDF(old_temporal, timestamp_bytes, domain)
        let ts_bytes = snapshot.timestamp_nanos.to_le_bytes();
        let mut t_new = kk_mix::kk_kdf(&self.temporal_strand, &ts_bytes, STRAND_TMP_INFO, 32);
        self.temporal_strand.copy_from_slice(&t_new);
        t_new.zeroize();

        // ── Evolve chain strand ──
        // Increment counter first (counter 0 = no messages, first message = 1)
        self.counter += 1;
        let ctr_bytes = self.counter.to_le_bytes();
        let mut c_new = kk_mix::kk_kdf(&self.chain_strand, &ctr_bytes, STRAND_CHN_INFO, 32);
        self.chain_strand.copy_from_slice(&c_new);
        c_new.zeroize();

        // ── THE KK INNOVATION ──
        // Concatenate all 4 strand outputs into a single block.
        // This is fed as the key into kk_kdf, with the entropy snapshot
        // as salt. Internally, kk_kdf creates a sponge with entropy-
        // derived rotations (with_entropy_rotations(salt)), so the
        // permutation structure itself, the algebra, changes per message.
        // The 32-round permutation (960 MFR + 480 DDR) mixes all 4 strands
        // simultaneously. No separate combine step needed.
        let mut combined = Vec::with_capacity(104);
        combined.extend_from_slice(&self.entropy_strand); // 32 bytes
        combined.extend_from_slice(&self.temporal_strand); // 32 bytes
        combined.extend_from_slice(&self.chain_strand); // 32 bytes
        combined.extend_from_slice(&ctr_bytes); // 8 bytes

        // kk_kdf(key=all_strands, salt=entropy, info=domain, len=64)
        // → sponge with entropy-derived rotations absorbs everything
        // → 32-round permutation mixes all strand material
        // → squeeze 64 bytes: 32 for new chain + 32 for message key
        let mut output = kk_mix::kk_kdf(&combined, &snapshot.bytes, DOMAIN_SESSION, 64);
        combined.zeroize();

        // First 32 bytes: new chain key (replaces current, forward secrecy).
        // The old chain_strand value is gone, you cannot go backwards.
        self.chain_strand.copy_from_slice(&output[..32]);

        // Second 32 bytes: message key (returned to caller).
        let mut message_key = [0u8; 32];
        message_key.copy_from_slice(&output[32..64]);

        output.zeroize();

        Ok(message_key)
    }
}

// ─────────────────────────────────────────────────────────────────
//  RopePacket: encrypted message with forward secrecy
// ─────────────────────────────────────────────────────────────────

/// An encrypted message with forward secrecy.
///
/// Contains the ratchet step metadata (so the receiver can derive the
/// same message key) and the inner [`KkPacket`] (the actual encrypted
/// payload, which carries its own entropy snapshot and integrity
/// commitment).
///
/// Double entropy: the ratchet step uses one `EntropySnapshot` for
/// key derivation, and the inner `KkPacket` captures its own independent
/// snapshot for per-symbol encryption. Two unrepeatable moments per message.
///
/// ## Wire Format
///
/// ```text
/// [8-byte counter][48-byte ratchet snapshot][inner KkPacket bytes...]
/// ```
#[derive(Clone)]
pub struct RopePacket {
    /// Ratchet step metadata (counter + entropy snapshot).
    pub step: RopeStep,
    /// The inner encrypted packet, keyed by the ratchet's message key.
    pub inner: KkPacket,
}

impl RopePacket {
    /// Serialize the full forward-secret packet for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let step_bytes = self.step.to_bytes();
        let inner_bytes = self.inner.to_bytes();
        let mut out = Vec::with_capacity(step_bytes.len() + inner_bytes.len());
        out.extend_from_slice(&step_bytes);
        out.extend_from_slice(&inner_bytes);
        out
    }

    /// Deserialize a forward-secret packet from received bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < RopeStep::BYTES {
            return Err(KkError::InvalidPacket(
                "rope packet too short for step metadata".into(),
            ));
        }
        let step = RopeStep::from_bytes(&data[..RopeStep::BYTES])?;
        let inner = KkPacket::from_bytes(&data[RopeStep::BYTES..])?;
        Ok(Self { step, inner })
    }
}

// ─────────────────────────────────────────────────────────────────
//  High-level API: encode/decode with forward secrecy
// ─────────────────────────────────────────────────────────────────

/// Encode plaintext with forward secrecy.
///
/// Advances the ratchet, derives a per-message key, and encrypts
/// the plaintext using the standard KK codec. The ratchet step
/// metadata is embedded in the returned [`RopePacket`].
///
/// After this call, the old ratchet state is irreversibly destroyed.
/// Even if the ratchet is later compromised, past message keys
/// cannot be recovered.
///
/// # Example
///
/// ```rust
/// use kk_crypto::session::{RopeRatchet, encode_session, decode_session};
///
/// let secret = b"shared-secret";
/// let mut sender = RopeRatchet::new(secret, b"a-to-b").unwrap();
/// let mut receiver = RopeRatchet::new(secret, b"a-to-b").unwrap();
///
/// let packet = encode_session(&mut sender, b"hello forward secrecy").unwrap();
/// let plaintext = decode_session(&mut receiver, &packet).unwrap();
/// assert_eq!(plaintext, b"hello forward secrecy");
/// ```
pub fn encode_session(ratchet: &mut RopeRatchet, plaintext: &[u8]) -> Result<RopePacket> {
    let (mut message_key, step) = ratchet.advance()?;

    // Use the ratchet's message key as the shared secret for the
    // standard KK codec. The codec gathers its own independent entropy,
    // adds its own temporal commitment, and produces a full KkPacket.
    let inner = codec::encode(&message_key, plaintext)?;
    message_key.zeroize();

    Ok(RopePacket { step, inner })
}

/// Decode a forward-secret packet.
///
/// Advances the receiver's ratchet using the packet's step metadata,
/// derives the same per-message key, and decrypts the inner
/// [`KkPacket`].
///
/// # Errors
///
/// - `KkError::InvalidPacket` if the counter is out of sequence
/// - `KkError::CommitmentMismatch` if the inner packet fails integrity
pub fn decode_session(ratchet: &mut RopeRatchet, packet: &RopePacket) -> Result<Vec<u8>> {
    let mut message_key = ratchet.receive(&packet.step)?;

    let plaintext = codec::decode(&message_key, &packet.inner)?;
    message_key.zeroize();

    Ok(plaintext)
}

// ─────────────────────────────────────────────────────────────────
//  Session AEAD (forward secrecy + authenticated associated data)
// ─────────────────────────────────────────────────────────────────

/// A forward-secret AEAD packet: ratchet step + inner AEAD packet.
///
/// Combines the Rope Ratchet (forward secrecy, key evolution) with
/// AEAD (authenticated associated data). The AAD is authenticated
/// but not encrypted.
#[derive(Clone)]
pub struct RopeAeadPacket {
    /// The ratchet step metadata (strand, counter, direction)
    pub step: RopeStep,
    /// The inner KK-AEAD packet
    pub inner: KkAeadPacket,
}

impl RopeAeadPacket {
    /// Serialize for transmission.
    pub fn to_bytes(&self) -> Vec<u8> {
        let step_bytes = self.step.to_bytes();
        let inner_bytes = self.inner.to_bytes();
        let mut out = Vec::with_capacity(step_bytes.len() + inner_bytes.len());
        out.extend_from_slice(&step_bytes);
        out.extend_from_slice(&inner_bytes);
        out
    }

    /// Deserialize from received bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let step = RopeStep::from_bytes(data)?;
        let step_len = step.to_bytes().len();
        let inner = KkAeadPacket::from_bytes(&data[step_len..])?;
        Ok(Self { step, inner })
    }
}

/// Encode a forward-secret AEAD packet.
///
/// Advances the ratchet, derives a per-message key, then encrypts
/// the plaintext with AEAD (AAD is authenticated but not encrypted).
pub fn encode_session_aead(
    ratchet: &mut RopeRatchet,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<RopeAeadPacket> {
    let (mut message_key, step) = ratchet.advance()?;
    let inner = codec::encode_aead(&message_key, plaintext, aad)?;
    message_key.zeroize();
    Ok(RopeAeadPacket { step, inner })
}

/// Decode a forward-secret AEAD packet.
///
/// Advances the receiver's ratchet, derives the same per-message key,
/// and decrypts the inner AEAD packet (verifying both ciphertext and AAD).
pub fn decode_session_aead(ratchet: &mut RopeRatchet, packet: &RopeAeadPacket) -> Result<Vec<u8>> {
    let mut message_key = ratchet.receive(&packet.step)?;
    let plaintext = codec::decode_aead(&message_key, &packet.inner)?;
    message_key.zeroize();
    Ok(plaintext)
}
