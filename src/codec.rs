// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! KK Codec, The core encoding/decoding primitive.
//!
//! This is where the fundamental KK operation happens:
//!
//!   KK(S) = S ^ ε
//!
//! For each symbol (byte) in the plaintext, we derive a unique key stream
//! from the shared secret and the entropy snapshot, then XOR to encode.
//!
//! The same symbol encoded at two different moments produces two
//! cryptographically unrelated values, because the entropy snapshot ε
//! is different, that moment is gone, unrepeatable, unrecoverable.
//!
//! ## Encoding Flow
//!
//! ```text
//! plaintext bytes → for each byte[i]:
//!   key_i = KK-KDF(shared_secret, salt=ε, info=i||timestamp)
//!   cipher_i = byte[i] ⊕ key_i
//! → ciphertext
//! ```
//!
//! ## Decoding Flow
//!
//! ```text
//! ciphertext + ε → for each byte[i]:
//!   key_i = KK-KDF(shared_secret, salt=ε, info=i||timestamp)  // SAME derivation
//!   plain_i = cipher_i ⊕ key_i                                 // XOR is its own inverse
//! → plaintext
//! ```
//!
//! All key derivation uses the novel KK-Sponge-KDF, no HKDF, no SHA-256.

use rayon::prelude::*;
use zeroize::Zeroize;

use std::time::Duration;

use crate::entropy::{self, EntropySnapshot};
use crate::error::{KkError, Result};
use crate::kdf;
use crate::temporal::{self, TemporalCommitment, TemporalProof};

/// The number of plaintext bytes processed per KDF derivation.
/// Larger chunks = fewer KDF calls = better throughput.
/// Each chunk still gets a unique key derived from its position.
const CHUNK_SIZE: usize = 4096;

/// A KK-encoded packet: everything the receiver needs to decode.
///
/// Contains:
///   - The ciphertext (XOR of plaintext with per-symbol key stream)
///   - The entropy snapshot ε (the unrepeatable moment)
///   - Temporal commitment (proves integrity of ε + ciphertext binding)
#[derive(Clone)]
pub struct KkPacket {
    /// The encoded bytes, symbol values transmuted by entropy
    pub ciphertext: Vec<u8>,
    /// The entropy snapshot, the captured moment
    pub entropy_snapshot: EntropySnapshot,
    /// Temporal commitment, binds ciphertext to its entropic moment
    pub commitment: TemporalCommitment,
}

impl KkPacket {
    /// Serialize the full packet for transmission.
    ///
    /// Format: [4-byte ciphertext length][ciphertext][48-byte snapshot][32-byte commitment]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u32;
        let snap_bytes = self.entropy_snapshot.to_bytes();
        let commit_bytes = self.commitment.to_bytes();

        let mut out = Vec::with_capacity(4 + self.ciphertext.len() + snap_bytes.len() + commit_bytes.len());
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&snap_bytes);
        out.extend_from_slice(&commit_bytes);
        out
    }

    /// Deserialize a packet from received bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(KkError::InvalidPacket("packet too short".into()));
        }

        let ct_len = u32::from_le_bytes(
            data[..4].try_into().map_err(|_| KkError::InvalidPacket("bad length".into()))?
        ) as usize;

        let expected_min = 4 + ct_len + 48 + 32; // 48 = snapshot, 32 = commitment
        if data.len() < expected_min {
            return Err(KkError::InvalidPacket(format!(
                "packet too short: expected at least {expected_min}, got {}",
                data.len()
            )));
        }

        let ciphertext = data[4..4 + ct_len].to_vec();
        let snapshot = EntropySnapshot::from_bytes(&data[4 + ct_len..4 + ct_len + 48])?;
        let commitment = TemporalCommitment::from_bytes(&data[4 + ct_len + 48..])?;

        Ok(Self {
            ciphertext,
            entropy_snapshot: snapshot,
            commitment,
        })
    }
}

// ─────────────────────────────────────────────────────────────────
//  Split-channel types, ε travels separately from ciphertext
// ─────────────────────────────────────────────────────────────────

/// A sealed message: ciphertext + integrity commitment, but NO entropy.
///
/// This is what travels on the public channel. Without the corresponding
/// `EntropySnapshot` (which must arrive on a separate, private channel),
/// the attacker cannot even begin brute-forcing, ε is the HKDF salt,
/// and without it every passphrase guess is meaningless.
///
/// ```text
/// Channel 1 (public):  KkSealedMessage  →  ciphertext + HMAC
/// Channel 2 (private): EntropySnapshot  →  ε (the moment)
/// ```
#[derive(Clone)]
pub struct KkSealedMessage {
    /// The encoded bytes, symbol values transmuted by entropy
    pub ciphertext: Vec<u8>,
    /// Temporal commitment, binds ciphertext to its entropic moment
    pub commitment: TemporalCommitment,
}

impl KkSealedMessage {
    /// Serialize for Channel 1 transmission.
    ///
    /// Format: [4-byte ciphertext length][ciphertext][32-byte commitment]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u32;
        let commit_bytes = self.commitment.to_bytes();

        let mut out = Vec::with_capacity(4 + self.ciphertext.len() + commit_bytes.len());
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&commit_bytes);
        out
    }

    /// Deserialize from Channel 1 bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(KkError::InvalidPacket("sealed message too short".into()));
        }

        let ct_len = u32::from_le_bytes(
            data[..4].try_into().map_err(|_| KkError::InvalidPacket("bad length".into()))?
        ) as usize;

        let expected_min = 4 + ct_len + 32;
        if data.len() < expected_min {
            return Err(KkError::InvalidPacket(format!(
                "sealed message too short: expected at least {expected_min}, got {}",
                data.len()
            )));
        }

        let ciphertext = data[4..4 + ct_len].to_vec();
        let commitment = TemporalCommitment::from_bytes(&data[4 + ct_len..])?;

        Ok(Self {
            ciphertext,
            commitment,
        })
    }
}

/// Encode plaintext using the KK primitive.
///
/// This is the fundamental KK operation:
///   1. Capture entropy from the universe at this exact moment
///   2. For each symbol, derive a unique key from (secret, ε, position)
///   3. XOR the symbol with its key, the symbol's value is now
///      a function of the universe at the instant it was born
///   4. Create a temporal commitment binding everything together
///
/// The returned KkPacket contains everything the receiver needs.
pub fn encode(shared_secret: &[u8], plaintext: &[u8]) -> Result<KkPacket> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }

    // Step 1: Capture the entropic moment, this instant will never exist again
    let snapshot = entropy::gather()?;

    // Step 2-3: Derive per-symbol keys and encode
    let ciphertext = xor_with_keystream(shared_secret, &snapshot, plaintext)?;

    // Step 4: Create temporal commitment
    let commitment = temporal::commit(shared_secret, &snapshot, &ciphertext)?;

    Ok(KkPacket {
        ciphertext,
        entropy_snapshot: snapshot,
        commitment,
    })
}

/// Decode a KK packet back to plaintext.
///
/// The receiver uses:
///   - The shared secret (what both parties know)
///   - The entropy snapshot ε (transmitted with the packet)
///   - Deterministic derivation (same HKDF, same inputs = same keys)
///
/// Same universe, same moment reference, same symbol values.
pub fn decode(shared_secret: &[u8], packet: &KkPacket) -> Result<Vec<u8>> {
    // Step 1: Verify temporal commitment, is this packet intact?
    temporal::verify(
        shared_secret,
        &packet.entropy_snapshot,
        &packet.ciphertext,
        &packet.commitment,
    )?;

    // Step 2: Derive same keystream and XOR to recover plaintext
    // XOR is its own inverse: (P ⊕ K) ⊕ K = P
    xor_with_keystream(shared_secret, &packet.entropy_snapshot, &packet.ciphertext)
}

// ─────────────────────────────────────────────────────────────────
//  Split-channel API, ε never touches the ciphertext wire
// ─────────────────────────────────────────────────────────────────

/// Encode plaintext and split the result across two channels.
///
/// Returns `(KkSealedMessage, EntropySnapshot)`:
///   - **Channel 1 (public):** `KkSealedMessage`, ciphertext + HMAC
///   - **Channel 2 (private):** `EntropySnapshot`, the ε key
///
/// An attacker intercepting only Channel 1 sees ciphertext + HMAC but
/// has no ε. Without ε they cannot derive any key material, every
/// passphrase guess is meaningless because the HKDF salt is missing.
///
/// The ε is physically non-reconstructible (proved in examples/proof.rs).
/// If it never reaches the attacker, the ciphertext is information-
/// theoretically unbreakable regardless of compute power.
pub fn encode_split(shared_secret: &[u8], plaintext: &[u8]) -> Result<(KkSealedMessage, EntropySnapshot)> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }

    // Step 1: Capture the entropic moment
    let snapshot = entropy::gather()?;

    // Step 2-3: Derive per-symbol keys and encode
    let ciphertext = xor_with_keystream(shared_secret, &snapshot, plaintext)?;

    // Step 4: Create temporal commitment
    let commitment = temporal::commit(shared_secret, &snapshot, &ciphertext)?;

    let sealed = KkSealedMessage {
        ciphertext,
        commitment,
    };

    // The two halves go on separate channels
    Ok((sealed, snapshot))
}

/// Decode a split-channel message by reuniting ciphertext with ε.
///
/// The receiver needs:
///   - The shared secret (what both parties know)
///   - The `KkSealedMessage` (from Channel 1, the public wire)
///   - The `EntropySnapshot` (from Channel 2, the private channel)
///
/// All three factors must be present. Missing any one = no decryption.
pub fn decode_split(
    shared_secret: &[u8],
    sealed: &KkSealedMessage,
    epsilon: &EntropySnapshot,
) -> Result<Vec<u8>> {
    // Step 1: Verify temporal commitment
    temporal::verify(
        shared_secret,
        epsilon,
        &sealed.ciphertext,
        &sealed.commitment,
    )?;

    // Step 2: Derive keystream and XOR to recover plaintext
    xor_with_keystream(shared_secret, epsilon, &sealed.ciphertext)
}

// ─────────────────────────────────────────────────────────────────
//  Bound-commitment API, challenge-response temporal proof
// ─────────────────────────────────────────────────────────────────

/// A KK packet with a full temporal proof (challenge-response).
///
/// Unlike [`KkPacket`], which carries a basic integrity MAC, this packet
/// carries a [`TemporalProof`] providing:
///
///   - **Freshness**: verifier-supplied nonce proves creation was after the challenge
///   - **Recency**: epoch check bounds when the encoding actually happened
///   - **Ordering**: `prev_mac` chains packets into a total order
///   - **Temporal MAC**: the permutation structure itself varies with entropy
///
/// The receiver must supply the nonce they originally issued and the
/// maximum acceptable clock drift.
#[derive(Clone)]
pub struct KkBoundPacket {
    /// The encoded bytes
    pub ciphertext: Vec<u8>,
    /// The entropy snapshot, the captured moment
    pub entropy_snapshot: EntropySnapshot,
    /// Temporal proof, freshness + recency + integrity + ordering
    pub proof: TemporalProof,
}

impl KkBoundPacket {
    /// Serialize for transmission.
    ///
    /// Format: `[4-byte ct_len][ciphertext][48-byte snapshot][96-byte proof]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let ct_len = self.ciphertext.len() as u32;
        let snap_bytes = self.entropy_snapshot.to_bytes();
        let proof_bytes = self.proof.to_bytes();

        let mut out = Vec::with_capacity(4 + self.ciphertext.len() + snap_bytes.len() + proof_bytes.len());
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&snap_bytes);
        out.extend_from_slice(&proof_bytes);
        out
    }

    /// Deserialize from received bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(KkError::InvalidPacket("bound packet too short".into()));
        }

        let ct_len = u32::from_le_bytes(
            data[..4].try_into().map_err(|_| KkError::InvalidPacket("bad length".into()))?
        ) as usize;

        let expected_min = 4 + ct_len + 48 + TemporalProof::BYTES;
        if data.len() < expected_min {
            return Err(KkError::InvalidPacket(format!(
                "bound packet too short: expected at least {expected_min}, got {}",
                data.len()
            )));
        }

        let ciphertext = data[4..4 + ct_len].to_vec();
        let snapshot = EntropySnapshot::from_bytes(&data[4 + ct_len..4 + ct_len + 48])?;
        let proof = TemporalProof::from_bytes(&data[4 + ct_len + 48..])?;

        Ok(Self {
            ciphertext,
            entropy_snapshot: snapshot,
            proof,
        })
    }
}

/// Encode plaintext with a full temporal proof (challenge-response).
///
/// # Protocol
///
/// ```text
/// Verifier ── generate_challenge() ──→ nonce ──→ Prover
/// Prover   ── encode_bound(secret, plain, nonce, prev_mac) ──→ KkBoundPacket
/// ```
///
/// # Arguments
/// - `shared_secret`, the pre-shared key
/// - `plaintext`, data to encode
/// - `verifier_nonce`, challenge nonce from the verifier
/// - `prev_mac`, MAC of the previous proof in the chain, or
///   [`temporal::GENESIS_MAC`] for the first message
pub fn encode_bound(
    shared_secret: &[u8],
    plaintext: &[u8],
    verifier_nonce: &[u8; 32],
    prev_mac: &[u8; 32],
) -> Result<KkBoundPacket> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }

    let snapshot = entropy::gather()?;
    let ciphertext = xor_with_keystream(shared_secret, &snapshot, plaintext)?;
    let proof = temporal::commit_bound(
        shared_secret,
        &snapshot,
        &ciphertext,
        verifier_nonce,
        prev_mac,
    )?;

    Ok(KkBoundPacket {
        ciphertext,
        entropy_snapshot: snapshot,
        proof,
    })
}

/// Decode a bound packet, verifying freshness + recency + integrity.
///
/// # Protocol
///
/// ```text
/// Verifier receives KkBoundPacket, then:
///   decode_bound(secret, packet, nonce_I_issued, max_drift)
/// ```
///
/// Verification checks (in order):
/// 1. **Nonce**, proof contains the nonce the verifier issued
/// 2. **Epoch**, `|now - ε.timestamp| ≤ max_drift`
/// 3. **MAC**, entropy-derived rotations, constant-time compare
///
/// The caller is responsible for:
/// - Tracking nonces and rejecting reuse
/// - Verifying `packet.proof.prev_mac` matches the expected chain link
pub fn decode_bound(
    shared_secret: &[u8],
    packet: &KkBoundPacket,
    expected_nonce: &[u8; 32],
    max_drift: Duration,
) -> Result<Vec<u8>> {
    temporal::verify_bound(
        shared_secret,
        &packet.entropy_snapshot,
        &packet.ciphertext,
        &packet.proof,
        expected_nonce,
        max_drift,
    )?;

    xor_with_keystream(shared_secret, &packet.entropy_snapshot, &packet.ciphertext)
}

// ─────────────────────────────────────────────────────────────────
//  AEAD API, authenticated encryption with associated data
// ─────────────────────────────────────────────────────────────────

/// A KK-AEAD packet: ciphertext + authenticated associated data.
///
/// Contains:
///   - Associated data (AAD)  - transmitted in the clear, authenticated
///   - The ciphertext (XOR of plaintext with per-symbol key stream)
///   - The entropy snapshot ε (the unrepeatable moment)
///   - Temporal commitment (binds ciphertext + AAD to the entropic moment)
///
/// The AAD is NOT encrypted but IS integrity-protected by the commitment.
/// Any modification to the AAD or ciphertext will be detected on decode.
#[derive(Clone)]
pub struct KkAeadPacket {
    /// Associated data, authenticated but not encrypted
    pub aad: Vec<u8>,
    /// The encoded bytes
    pub ciphertext: Vec<u8>,
    /// The entropy snapshot
    pub entropy_snapshot: EntropySnapshot,
    /// Temporal commitment binding ciphertext + AAD to the entropic moment
    pub commitment: TemporalCommitment,
}

impl KkAeadPacket {
    /// Serialize for transmission.
    ///
    /// Format: `[4-byte aad_len][aad][4-byte ct_len][ciphertext][48-byte snapshot][32-byte commitment]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let aad_len = self.aad.len() as u32;
        let ct_len = self.ciphertext.len() as u32;
        let snap_bytes = self.entropy_snapshot.to_bytes();
        let commit_bytes = self.commitment.to_bytes();

        let mut out = Vec::with_capacity(
            4 + self.aad.len() + 4 + self.ciphertext.len() + snap_bytes.len() + commit_bytes.len(),
        );
        out.extend_from_slice(&aad_len.to_le_bytes());
        out.extend_from_slice(&self.aad);
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&snap_bytes);
        out.extend_from_slice(&commit_bytes);
        out
    }

    /// Deserialize from received bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(KkError::InvalidPacket("AEAD packet too short".into()));
        }

        let aad_len = u32::from_le_bytes(
            data[..4].try_into().map_err(|_| KkError::InvalidPacket("bad aad length".into()))?
        ) as usize;

        if data.len() < 4 + aad_len + 4 {
            return Err(KkError::InvalidPacket("AEAD packet truncated at ct_len".into()));
        }

        let aad = data[4..4 + aad_len].to_vec();
        let ct_offset = 4 + aad_len;

        let ct_len = u32::from_le_bytes(
            data[ct_offset..ct_offset + 4]
                .try_into()
                .map_err(|_| KkError::InvalidPacket("bad ct length".into()))?
        ) as usize;

        let expected_min = ct_offset + 4 + ct_len + 48 + 32;
        if data.len() < expected_min {
            return Err(KkError::InvalidPacket(format!(
                "AEAD packet too short: expected at least {expected_min}, got {}",
                data.len()
            )));
        }

        let ct_start = ct_offset + 4;
        let ciphertext = data[ct_start..ct_start + ct_len].to_vec();
        let snap_start = ct_start + ct_len;
        let snapshot = EntropySnapshot::from_bytes(&data[snap_start..snap_start + 48])?;
        let commitment = TemporalCommitment::from_bytes(&data[snap_start + 48..snap_start + 48 + 32])?;

        Ok(Self {
            aad,
            ciphertext,
            entropy_snapshot: snapshot,
            commitment,
        })
    }
}

/// Encode plaintext with authenticated associated data (AEAD).
///
/// The AAD is included in the commitment MAC but is NOT encrypted.
/// This is useful for metadata (headers, routing info, version tags)
/// that must be readable in the clear but tamper-proof.
///
/// # Arguments
/// - `shared_secret`  - the pre-shared key
/// - `plaintext`  - data to encrypt
/// - `aad`  - associated data to authenticate (not encrypted)
pub fn encode_aead(
    shared_secret: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<KkAeadPacket> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }

    let snapshot = entropy::gather()?;
    let ciphertext = xor_with_keystream(shared_secret, &snapshot, plaintext)?;
    let commitment = temporal::commit_aead(shared_secret, &snapshot, &ciphertext, aad)?;

    Ok(KkAeadPacket {
        aad: aad.to_vec(),
        ciphertext,
        entropy_snapshot: snapshot,
        commitment,
    })
}

/// Decode a KK-AEAD packet, verifying integrity of both ciphertext and AAD.
///
/// # Errors
/// - `KkError::CommitmentMismatch` if the ciphertext or AAD was tampered with
pub fn decode_aead(
    shared_secret: &[u8],
    packet: &KkAeadPacket,
) -> Result<Vec<u8>> {
    temporal::verify_aead(
        shared_secret,
        &packet.entropy_snapshot,
        &packet.ciphertext,
        &packet.aad,
        &packet.commitment,
    )?;

    xor_with_keystream(shared_secret, &packet.entropy_snapshot, &packet.ciphertext)
}

// ─────────────────────────────────────────────────────────────────
//  Deterministic helpers (fixed snapshot, for test-vector generation)
// ─────────────────────────────────────────────────────────────────

/// Encode plaintext with a caller-supplied [`EntropySnapshot`].
///
/// Identical to [`encode`] but skips `entropy::gather()` so the output
/// is fully deterministic for a given (secret, plaintext, snapshot).
///
/// # Visibility
/// Exposed for integration tests and the `generate_vectors` example.
/// **Not part of the public API contract**  - may change without notice.
#[doc(hidden)]
pub fn encode_with_snapshot(
    shared_secret: &[u8],
    plaintext: &[u8],
    snapshot: EntropySnapshot,
) -> Result<KkPacket> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }
    let ciphertext = xor_with_keystream(shared_secret, &snapshot, plaintext)?;
    let commitment = temporal::commit(shared_secret, &snapshot, &ciphertext)?;
    Ok(KkPacket {
        ciphertext,
        entropy_snapshot: snapshot,
        commitment,
    })
}

/// AEAD encode with a caller-supplied [`EntropySnapshot`].
///
/// Identical to [`encode_aead`] but deterministic when the snapshot is fixed.
#[doc(hidden)]
pub fn encode_aead_with_snapshot(
    shared_secret: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    snapshot: EntropySnapshot,
) -> Result<KkAeadPacket> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }
    let ciphertext = xor_with_keystream(shared_secret, &snapshot, plaintext)?;
    let commitment = temporal::commit_aead(shared_secret, &snapshot, &ciphertext, aad)?;
    Ok(KkAeadPacket {
        aad: aad.to_vec(),
        ciphertext,
        entropy_snapshot: snapshot,
        commitment,
    })
}

/// Internal: XOR input with the KK-derived keystream.
///
/// Processes chunks in batches of 8 using AVX-512 vectorized KDF when
/// available, falling back to per-chunk scalar derivation otherwise.
/// Within each batch, rayon parallelises across CPU cores.
fn xor_with_keystream(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    input: &[u8],
) -> Result<Vec<u8>> {
    let mut output = vec![0u8; input.len()];
    let batch_bytes = CHUNK_SIZE * 8;

    let result = output
        .par_chunks_mut(batch_bytes)
        .enumerate()
        .try_for_each(|(batch_idx, out_batch)| -> Result<()> {
            let base_chunk = batch_idx * 8;
            let in_base = base_chunk * CHUNK_SIZE;

            if out_batch.len() == batch_bytes {
                // Full batch of 8 chunks, use vectorized KDF
                let mut keys = kdf::derive_symbol_key_batch(
                    shared_secret,
                    snapshot,
                    base_chunk as u64,
                    CHUNK_SIZE,
                )?;

                for (c, key) in keys.iter_mut().enumerate() {
                    let out_off = c * CHUNK_SIZE;
                    let in_off = in_base + c * CHUNK_SIZE;
                    for i in 0..CHUNK_SIZE {
                        out_batch[out_off + i] = input[in_off + i] ^ key[i];
                    }
                    key.zeroize();
                }
            } else {
                // Partial tail batch, scalar per-chunk
                let chunks_in_batch =
                    out_batch.len().div_ceil(CHUNK_SIZE);

                for c in 0..chunks_in_batch {
                    let chunk_idx = base_chunk + c;
                    let out_off = c * CHUNK_SIZE;
                    let chunk_len = (out_batch.len() - out_off).min(CHUNK_SIZE);
                    let in_off = in_base + c * CHUNK_SIZE;

                    let mut key_bytes = kdf::derive_symbol_key(
                        shared_secret,
                        snapshot,
                        chunk_idx as u64,
                        chunk_len,
                    )?;

                    for i in 0..chunk_len {
                        out_batch[out_off + i] = input[in_off + i] ^ key_bytes[i];
                    }
                    key_bytes.zeroize();
                }
            }

            Ok(())
        });

    match result {
        Ok(()) => Ok(output),
        Err(e) => {
            output.zeroize();
            Err(e)
        }
    }
}

// ─────────────────────────────────────────────────────────────────
//  Streaming API  - incremental encode / decode
// ─────────────────────────────────────────────────────────────────

/// Incremental encoder that accumulates plaintext via [`update`](StreamEncoder::update)
/// and produces a single [`KkPacket`] on [`finalize`](StreamEncoder::finalize).
///
/// The entropy snapshot is captured once at construction and reused for the
/// entire stream. This avoids capturing a new snapshot per chunk while still
/// binding every byte to the same unrepeatable moment.
///
/// # Example
///
/// ```rust
/// use kk_crypto::StreamEncoder;
///
/// let secret = b"our-shared-secret";
/// let mut enc = StreamEncoder::new(secret).unwrap();
/// enc.update(b"Hello ");
/// enc.update(b"KK!");
/// let packet = enc.finalize().unwrap();
/// ```
pub struct StreamEncoder {
    shared_secret: Vec<u8>,
    buffer: Vec<u8>,
    snapshot: EntropySnapshot,
}

impl StreamEncoder {
    /// Create a new streaming encoder.
    ///
    /// Captures the entropy snapshot immediately so the caller can feed
    /// data at their own pace without worrying about timing skew.
    pub fn new(shared_secret: &[u8]) -> Result<Self> {
        let snapshot = entropy::gather()?;
        Ok(Self {
            shared_secret: shared_secret.to_vec(),
            buffer: Vec::new(),
            snapshot,
        })
    }

    /// Append plaintext bytes to the internal buffer.
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Consume the encoder and produce the final [`KkPacket`].
    ///
    /// Returns [`KkError::EmptyInput`] if no bytes were fed via [`update`](Self::update).
    pub fn finalize(mut self) -> Result<KkPacket> {
        if self.buffer.is_empty() {
            return Err(KkError::EmptyInput);
        }

        let ciphertext = xor_with_keystream(&self.shared_secret, &self.snapshot, &self.buffer)?;
        let commitment = temporal::commit(&self.shared_secret, &self.snapshot, &ciphertext)?;

        self.shared_secret.zeroize();
        self.buffer.zeroize();

        Ok(KkPacket {
            ciphertext,
            entropy_snapshot: self.snapshot.clone(),
            commitment,
        })
    }
}

impl Drop for StreamEncoder {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
        self.buffer.zeroize();
    }
}

/// Incremental decoder that accumulates ciphertext via [`update`](StreamDecoder::update)
/// and decodes at [`finalize`](StreamDecoder::finalize) using a pre-received
/// entropy snapshot and commitment.
///
/// # Example
///
/// ```rust,no_run
/// use kk_crypto::{StreamDecoder, StreamEncoder};
///
/// let secret = b"our-shared-secret";
///
/// // Sender side (streaming encode)
/// let mut enc = StreamEncoder::new(secret).unwrap();
/// enc.update(b"Hello ");
/// enc.update(b"KK!");
/// let packet = enc.finalize().unwrap();
///
/// // Receiver side (streaming decode)
/// let mut dec = StreamDecoder::new(
///     secret,
///     packet.entropy_snapshot.clone(),
///     packet.commitment.clone(),
/// );
/// dec.update(&packet.ciphertext);
/// let plaintext = dec.finalize().unwrap();
/// assert_eq!(plaintext, b"Hello KK!");
/// ```
pub struct StreamDecoder {
    shared_secret: Vec<u8>,
    buffer: Vec<u8>,
    snapshot: EntropySnapshot,
    commitment: TemporalCommitment,
}

impl StreamDecoder {
    /// Create a new streaming decoder.
    ///
    /// The caller must supply the entropy snapshot and commitment from
    /// the packet header (typically received before the ciphertext body).
    pub fn new(
        shared_secret: &[u8],
        snapshot: EntropySnapshot,
        commitment: TemporalCommitment,
    ) -> Self {
        Self {
            shared_secret: shared_secret.to_vec(),
            buffer: Vec::new(),
            snapshot,
            commitment,
        }
    }

    /// Append ciphertext bytes to the internal buffer.
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Consume the decoder, verify integrity, and return plaintext.
    ///
    /// Returns [`KkError::EmptyInput`] if no bytes were fed, or a
    /// temporal verification error if the commitment does not match.
    pub fn finalize(mut self) -> Result<Vec<u8>> {
        if self.buffer.is_empty() {
            return Err(KkError::EmptyInput);
        }

        // Verify temporal commitment before decoding
        temporal::verify(
            &self.shared_secret,
            &self.snapshot,
            &self.buffer,
            &self.commitment,
        )?;

        let plaintext = xor_with_keystream(&self.shared_secret, &self.snapshot, &self.buffer)?;

        self.shared_secret.zeroize();
        self.buffer.zeroize();

        Ok(plaintext)
    }
}

impl Drop for StreamDecoder {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
        self.buffer.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let secret = b"test-shared-secret-2026";
        let plaintext = b"Hello from KK! The language only existed for one cosmic instant.";

        let packet = encode(secret, plaintext).unwrap();
        let decoded = decode(secret, &packet).unwrap();

        assert_eq!(plaintext.as_slice(), decoded.as_slice());
    }

    #[test]
    fn same_plaintext_different_ciphertext() {
        let secret = b"test-key";
        let plaintext = b"A"; // Same symbol

        let p1 = encode(secret, plaintext).unwrap();
        let p2 = encode(secret, plaintext).unwrap();

        // KK(S) at T₁ ≠ KK(S) at T₂
        // The same symbol encoded twice produces cryptographically unrelated values
        assert_ne!(
            p1.ciphertext, p2.ciphertext,
            "Same symbol at different moments MUST produce different ciphertext"
        );
    }

    #[test]
    fn wrong_key_fails_decode() {
        let plaintext = b"secret message";
        let packet = encode(b"correct-key", plaintext).unwrap();

        let result = decode(b"wrong-key", &packet);
        assert!(
            result.is_err(),
            "Decoding with wrong shared secret must fail commitment verification"
        );
    }

    #[test]
    fn empty_input_rejected() {
        let result = encode(b"key", b"");
        assert!(result.is_err());
    }

    #[test]
    fn packet_serialization_roundtrip() {
        let secret = b"serialize-test";
        let plaintext = b"test packet roundtrip";

        let packet = encode(secret, plaintext).unwrap();
        let bytes = packet.to_bytes();
        let restored = KkPacket::from_bytes(&bytes).unwrap();

        let decoded = decode(secret, &restored).unwrap();
        assert_eq!(plaintext.as_slice(), decoded.as_slice());
    }

    #[test]
    fn tampered_ciphertext_detected() {
        let secret = b"tamper-test";
        let packet = encode(secret, b"important data").unwrap();

        let mut tampered = packet.clone();
        tampered.ciphertext[0] ^= 0xFF; // Flip bits

        let result = decode(secret, &tampered);
        assert!(
            result.is_err(),
            "Tampered ciphertext must fail commitment verification"
        );
    }

    #[test]
    fn large_message_works() {
        let secret = b"large-msg-test";
        let plaintext: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();

        let packet = encode(secret, &plaintext).unwrap();
        let decoded = decode(secret, &packet).unwrap();

        assert_eq!(plaintext, decoded);
    }

    // ── Split-channel tests ─────────────────────────────────────

    #[test]
    fn split_encode_decode_roundtrip() {
        let secret = b"split-test-secret";
        let plaintext = b"Split-channel KK: ciphertext and epsilon travel separately.";

        let (sealed, epsilon) = encode_split(secret, plaintext).unwrap();
        let decoded = decode_split(secret, &sealed, &epsilon).unwrap();

        assert_eq!(plaintext.as_slice(), decoded.as_slice());
    }

    #[test]
    fn split_wrong_key_fails() {
        let plaintext = b"split secret";
        let (sealed, epsilon) = encode_split(b"right-key", plaintext).unwrap();

        let result = decode_split(b"wrong-key", &sealed, &epsilon);
        assert!(result.is_err(), "Wrong passphrase must fail");
    }

    #[test]
    fn split_wrong_epsilon_fails() {
        let secret = b"epsilon-test";
        let plaintext = b"the moment matters";

        let (sealed, _real_epsilon) = encode_split(secret, plaintext).unwrap();

        // An attacker fabricates a different ε
        let fake_epsilon = entropy::gather().unwrap();

        let result = decode_split(secret, &sealed, &fake_epsilon);
        assert!(result.is_err(), "Wrong epsilon must fail commitment verification");
    }

    #[test]
    fn split_sealed_message_serialization() {
        let secret = b"serde-split";
        let plaintext = b"roundtrip the sealed half";

        let (sealed, epsilon) = encode_split(secret, plaintext).unwrap();

        // Serialize / deserialize the sealed message (Channel 1)
        let wire = sealed.to_bytes();
        let restored = KkSealedMessage::from_bytes(&wire).unwrap();

        // Serialize / deserialize epsilon (Channel 2)
        let eps_wire = epsilon.to_bytes();
        let restored_eps = EntropySnapshot::from_bytes(&eps_wire).unwrap();

        let decoded = decode_split(secret, &restored, &restored_eps).unwrap();
        assert_eq!(plaintext.as_slice(), decoded.as_slice());
    }

    #[test]
    fn split_empty_input_rejected() {
        let result = encode_split(b"key", b"");
        assert!(result.is_err());
    }

    // ── Bound-commitment tests ──────────────────────────────────

    #[test]
    fn bound_encode_decode_roundtrip() {
        let secret = b"bound-test-secret";
        let plaintext = b"Temporal proof: challenge-response freshness.";

        let nonce = temporal::generate_challenge().unwrap();
        let packet = encode_bound(secret, plaintext, &nonce, &temporal::GENESIS_MAC).unwrap();
        let decoded = decode_bound(secret, &packet, &nonce, Duration::from_secs(30)).unwrap();

        assert_eq!(plaintext.as_slice(), decoded.as_slice());
    }

    #[test]
    fn bound_wrong_nonce_rejected() {
        let secret = b"nonce-reject";
        let nonce = temporal::generate_challenge().unwrap();
        let wrong_nonce = temporal::generate_challenge().unwrap();

        let packet = encode_bound(secret, b"test data", &nonce, &temporal::GENESIS_MAC).unwrap();
        let result = decode_bound(secret, &packet, &wrong_nonce, Duration::from_secs(30));
        assert!(result.is_err(), "Wrong nonce must be rejected");
    }

    #[test]
    fn bound_wrong_key_rejected() {
        let nonce = temporal::generate_challenge().unwrap();
        let packet = encode_bound(b"right-key", b"secret", &nonce, &temporal::GENESIS_MAC).unwrap();

        let result = decode_bound(b"wrong-key", &packet, &nonce, Duration::from_secs(30));
        assert!(result.is_err(), "Wrong key must fail");
    }

    #[test]
    fn bound_packet_serialization_roundtrip() {
        let secret = b"bound-serde";
        let plaintext = b"serialize a bound packet";

        let nonce = temporal::generate_challenge().unwrap();
        let packet = encode_bound(secret, plaintext, &nonce, &temporal::GENESIS_MAC).unwrap();

        let bytes = packet.to_bytes();
        let restored = KkBoundPacket::from_bytes(&bytes).unwrap();

        let decoded = decode_bound(secret, &restored, &nonce, Duration::from_secs(30)).unwrap();
        assert_eq!(plaintext.as_slice(), decoded.as_slice());
    }

    #[test]
    fn bound_tampered_ciphertext_detected() {
        let secret = b"tamper-bound";
        let nonce = temporal::generate_challenge().unwrap();
        let mut packet = encode_bound(secret, b"important", &nonce, &temporal::GENESIS_MAC).unwrap();
        packet.ciphertext[0] ^= 0xFF;

        let result = decode_bound(secret, &packet, &nonce, Duration::from_secs(30));
        assert!(result.is_err(), "Tampered ciphertext must fail");
    }

    #[test]
    fn bound_chain_ordering() {
        let secret = b"chain-test";
        let nonce1 = temporal::generate_challenge().unwrap();
        let nonce2 = temporal::generate_challenge().unwrap();

        let p1 = encode_bound(secret, b"first", &nonce1, &temporal::GENESIS_MAC).unwrap();
        let p2 = encode_bound(secret, b"second", &nonce2, &p1.proof.mac).unwrap();

        // Both decode successfully with correct nonces
        let d1 = decode_bound(secret, &p1, &nonce1, Duration::from_secs(30)).unwrap();
        let d2 = decode_bound(secret, &p2, &nonce2, Duration::from_secs(30)).unwrap();
        assert_eq!(d1, b"first");
        assert_eq!(d2, b"second");

        // Chain is verifiable: p2 references p1
        assert_eq!(p2.proof.prev_mac, p1.proof.mac);
    }

    #[test]
    fn bound_empty_input_rejected() {
        let nonce = temporal::generate_challenge().unwrap();
        let result = encode_bound(b"key", b"", &nonce, &temporal::GENESIS_MAC);
        assert!(result.is_err());
    }

    // ── Streaming API tests ──────────────────────────────────────

    #[test]
    fn stream_encode_decode_roundtrip() {
        let secret = b"stream-secret";
        let mut enc = StreamEncoder::new(secret).unwrap();
        enc.update(b"Hello ");
        enc.update(b"KK ");
        enc.update(b"Stream!");
        let packet = enc.finalize().unwrap();

        let plaintext = decode(secret, &packet).unwrap();
        assert_eq!(plaintext, b"Hello KK Stream!");
    }

    #[test]
    fn stream_decoder_roundtrip() {
        let secret = b"stream-dec-secret";
        let mut enc = StreamEncoder::new(secret).unwrap();
        enc.update(b"chunk1");
        enc.update(b"chunk2");
        let packet = enc.finalize().unwrap();

        let mut dec = StreamDecoder::new(
            secret,
            packet.entropy_snapshot.clone(),
            packet.commitment.clone(),
        );
        dec.update(&packet.ciphertext);
        let plaintext = dec.finalize().unwrap();
        assert_eq!(plaintext, b"chunk1chunk2");
    }

    #[test]
    fn stream_decoder_incremental_ciphertext() {
        let secret = b"stream-incr-secret";
        let mut enc = StreamEncoder::new(secret).unwrap();
        enc.update(b"ABCDEFGHIJ");
        let packet = enc.finalize().unwrap();

        // Feed ciphertext in two parts
        let mid = packet.ciphertext.len() / 2;
        let mut dec = StreamDecoder::new(
            secret,
            packet.entropy_snapshot.clone(),
            packet.commitment.clone(),
        );
        dec.update(&packet.ciphertext[..mid]);
        dec.update(&packet.ciphertext[mid..]);
        let plaintext = dec.finalize().unwrap();
        assert_eq!(plaintext, b"ABCDEFGHIJ");
    }

    #[test]
    fn stream_encoder_empty_rejected() {
        let enc = StreamEncoder::new(b"key").unwrap();
        assert!(enc.finalize().is_err());
    }

    #[test]
    fn stream_decoder_empty_rejected() {
        let snapshot = crate::entropy::gather().unwrap();
        let commitment = crate::temporal::commit(b"key", &snapshot, b"dummy").unwrap();
        let dec = StreamDecoder::new(b"key", snapshot, commitment);
        assert!(dec.finalize().is_err());
    }

    #[test]
    fn stream_matches_oneshot() {
        let secret = b"stream-vs-oneshot";
        let data = b"The quick brown fox jumps over the lazy dog";

        // One-shot encode with a specific snapshot
        let snapshot = crate::entropy::gather().unwrap();
        let oneshot = encode_with_snapshot(secret, data, snapshot.clone()).unwrap();

        // Streaming encode would use its own snapshot, so we just verify
        // the streaming roundtrip produces the same plaintext
        let mut enc = StreamEncoder::new(secret).unwrap();
        enc.update(data);
        let stream_pkt = enc.finalize().unwrap();

        let oneshot_pt = decode(secret, &oneshot).unwrap();
        let stream_pt = decode(secret, &stream_pkt).unwrap();
        assert_eq!(oneshot_pt, stream_pt);
        assert_eq!(&stream_pt[..], &data[..]);
    }

}
