// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

//! Temporal commitment and proof system for KK.
//!
//! Two tiers:
//!
//! ## `TemporalCommitment` (basic  - the original API)
//!
//! A standard MAC binding (ciphertext, entropy snapshot, shared secret).
//! Guarantees **integrity** and **authentication**, but:
//!   - Does NOT prove *when* the commitment was created (sender controls timestamp)
//!   - Does NOT prevent replay (same triple verifies forever)
//!   - MAC uses default rotations (not temporal-variant)
//!
//! Use when you only need tamper detection between cooperating parties.
//!
//! ## `TemporalProof` (bound  - the real thing)
//!
//! A challenge-response commitment with four verifiable properties:
//!
//! | Property   | Mechanism                                           |
//! |------------|-----------------------------------------------------|
//! | Integrity  | MAC over (nonce ‖ prev_mac ‖ ε ‖ ciphertext)       |
//! | Freshness  | Verifier-supplied nonce proves creation was *after* it was issued |
//! | Recency    | Verifier's clock checks `|now - ε.timestamp| < max_drift` |
//! | Ordering   | `prev_mac` chains proofs into a total order         |
//!
//! The MAC uses **entropy-derived rotations**, so the permutation that
//! produced the tag only existed at that entropic moment  - the algebra
//! itself is temporal.
//!
//! Built entirely from the KK permutation  - no HMAC, no SHA-256.

use rand::RngCore;
use std::time::Duration;

use crate::entropy::EntropySnapshot;
use crate::error::{KkError, Result};
use crate::kdf;
use crate::kk_mix;
use zeroize::Zeroize;

/// The prev_mac value for the first proof in a chain.
pub const GENESIS_MAC: [u8; 32] = [0u8; 32];

// ─────────────────────────────────────────────────────────────────
//  Basic commitment (original API  - preserved for backward compat)
// ─────────────────────────────────────────────────────────────────

/// A basic MAC commitment binding ciphertext to its entropy snapshot.
///
/// **What this proves:**
///   - The entropy snapshot ε was used with this shared secret
///   - The ciphertext hasn't been tampered with
///
/// **What this does NOT prove:**
///   - When the commitment was created (sender controls the timestamp)
///   - That this is a fresh commitment (replays verify indefinitely)
///
/// For provable temporal guarantees, use [`TemporalProof`] instead.
#[derive(Clone, Debug)]
pub struct TemporalCommitment {
    pub mac: [u8; 32],
}

impl TemporalCommitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.mac.to_vec()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 {
            return Err(KkError::InvalidPacket("commitment too short".into()));
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[..32]);
        Ok(Self { mac })
    }
}

/// Create a basic commitment (integrity only, no temporal proof).
///
/// See [`TemporalCommitment`] for what this does and does not prove.
pub fn commit(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    ciphertext: &[u8],
) -> Result<TemporalCommitment> {
    let mut commit_key = kdf::derive_commitment_key(shared_secret, snapshot)?;

    let mut message = Vec::with_capacity(32 + 16 + ciphertext.len());
    message.extend_from_slice(&snapshot.bytes);
    message.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
    message.extend_from_slice(ciphertext);

    let mac_bytes = kk_mix::kk_mac(&commit_key, &message);
    commit_key.zeroize();

    Ok(TemporalCommitment { mac: mac_bytes })
}

/// Verify a basic commitment (integrity only).
pub fn verify(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    ciphertext: &[u8],
    commitment: &TemporalCommitment,
) -> Result<()> {
    let mut commit_key = kdf::derive_commitment_key(shared_secret, snapshot)?;

    let mut message = Vec::with_capacity(32 + 16 + ciphertext.len());
    message.extend_from_slice(&snapshot.bytes);
    message.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
    message.extend_from_slice(ciphertext);

    let verified = kk_mix::kk_mac_verify(&commit_key, &message, &commitment.mac);
    commit_key.zeroize();

    if verified {
        Ok(())
    } else {
        Err(KkError::CommitmentMismatch)
    }
}

// ─────────────────────────────────────────────────────────────────
//  Temporal Proof (the real thing)
// ─────────────────────────────────────────────────────────────────

/// A temporal proof with verifiable freshness, recency, and ordering.
///
/// ## What this proves
///
/// 1. **Integrity**  - the ciphertext and entropy snapshot have not been
///    modified since the proof was created.
/// 2. **Freshness**  - the proof was created *after* the verifier issued
///    its challenge nonce (prevents replay).
/// 3. **Recency**  - the claimed `ε.timestamp` is within `max_drift` of
///    the verifier's clock at verification time.
/// 4. **Ordering**  - if `prev_mac` is non-genesis, this proof was created
///    after the proof whose MAC it references.
///
/// ## How it works
///
/// ```text
/// commit_key = KK-KDF(shared_secret, ε.bytes, "KK-commit-v1")
/// message    = nonce || prev_mac || ε.bytes || ε.timestamp || ciphertext
/// mac        = KK-MAC-with-entropy(commit_key, message, ε.bytes)
/// ```
///
/// The MAC runs on a sponge whose *rotation schedule* is derived from
/// `ε.bytes`  - the permutation structure itself is temporal, not just
/// the data flowing through it.
///
/// ## Protocol
///
/// ```text
/// Verifier ──── challenge nonce ──→ Prover
/// Prover   ──── KkBoundPacket   ──→ Verifier
/// Verifier checks: MAC ✓  epoch ✓  nonce ✓  chain ✓
/// ```
#[derive(Clone, Debug)]
pub struct TemporalProof {
    /// MAC binding nonce + chain + entropy + ciphertext.
    pub mac: [u8; 32],
    /// Verifier-supplied freshness nonce (prevents replay).
    pub nonce: [u8; 32],
    /// MAC of the previous proof in the chain ([`GENESIS_MAC`] for the first).
    pub prev_mac: [u8; 32],
}

impl TemporalProof {
    /// Serialized size in bytes: 32 (mac) + 32 (nonce) + 32 (prev_mac).
    pub const BYTES: usize = 96;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::BYTES);
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.prev_mac);
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < Self::BYTES {
            return Err(KkError::InvalidPacket(format!(
                "temporal proof too short: need {}, got {}",
                Self::BYTES,
                data.len()
            )));
        }
        let mut mac = [0u8; 32];
        let mut nonce = [0u8; 32];
        let mut prev_mac = [0u8; 32];
        mac.copy_from_slice(&data[..32]);
        nonce.copy_from_slice(&data[32..64]);
        prev_mac.copy_from_slice(&data[64..96]);
        Ok(Self { mac, nonce, prev_mac })
    }
}

/// Generate a cryptographic challenge nonce for the verifier.
///
/// The verifier calls this, sends the nonce to the prover, and later
/// checks that the proof contains it. This proves the proof was created
/// *after* the nonce was issued.
///
/// The verifier MUST track issued nonces and reject duplicates to prevent
/// replay. Each nonce should be used exactly once.
pub fn generate_challenge() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| KkError::EntropyFailure(format!("nonce generation: {e}")))?;
    Ok(nonce)
}

/// Create a temporal proof with verifiable freshness and ordering.
///
/// # Arguments
/// - `shared_secret`  - the pre-shared key
/// - `snapshot`  - the entropy snapshot captured during encoding
/// - `ciphertext`  - the encoded bytes
/// - `verifier_nonce`  - the challenge nonce from the verifier
/// - `prev_mac`  - MAC of the previous proof in the chain, or
///   [`GENESIS_MAC`] for the first proof
pub fn commit_bound(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    ciphertext: &[u8],
    verifier_nonce: &[u8; 32],
    prev_mac: &[u8; 32],
) -> Result<TemporalProof> {
    let mut commit_key = kdf::derive_commitment_key(shared_secret, snapshot)?;

    // Build the bound message: nonce || prev_mac || ε.bytes || ε.timestamp || ciphertext
    let mut message = Vec::with_capacity(32 + 32 + 32 + 16 + ciphertext.len());
    message.extend_from_slice(verifier_nonce);
    message.extend_from_slice(prev_mac);
    message.extend_from_slice(&snapshot.bytes);
    message.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
    message.extend_from_slice(ciphertext);

    // MAC with entropy-derived rotations  - the algebra itself is temporal
    let mac_bytes = kk_mix::kk_mac_with_entropy(&commit_key, &message, &snapshot.bytes);
    commit_key.zeroize();

    Ok(TemporalProof {
        mac: mac_bytes,
        nonce: *verifier_nonce,
        prev_mac: *prev_mac,
    })
}

/// Verify a temporal proof: integrity + freshness + recency + chain.
///
/// # Arguments
/// - `shared_secret`  - the pre-shared key
/// - `snapshot`  - the entropy snapshot from the packet
/// - `ciphertext`  - the encoded bytes from the packet
/// - `proof`  - the temporal proof to verify
/// - `expected_nonce`  - the nonce the verifier originally issued
/// - `max_drift`  - maximum acceptable clock drift
///
/// # Verification steps
/// 1. **Nonce match**  - `proof.nonce == expected_nonce` (freshness)
/// 2. **Epoch check**  - `|now - ε.timestamp| ≤ max_drift` (recency)
/// 3. **MAC verify**  - recompute and constant-time compare (integrity)
///
/// The caller is responsible for:
/// - Tracking issued nonces and rejecting reuse ([`KkError::StaleNonce`])
/// - Verifying `proof.prev_mac` matches the previous proof's MAC (chain)
pub fn verify_bound(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    ciphertext: &[u8],
    proof: &TemporalProof,
    expected_nonce: &[u8; 32],
    max_drift: Duration,
) -> Result<()> {
    // 1. Freshness: nonce must match the one we issued
    if proof.nonce != *expected_nonce {
        return Err(KkError::StaleNonce);
    }

    // 2. Recency: claimed timestamp must be within max_drift of our clock
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    let drift = now_nanos.abs_diff(snapshot.timestamp_nanos);

    if drift > max_drift.as_nanos() {
        return Err(KkError::EpochDrift {
            claimed_nanos: snapshot.timestamp_nanos,
            drift_nanos: drift,
            max_nanos: max_drift.as_nanos(),
        });
    }

    // 3. Integrity: recompute MAC with entropy-derived rotations
    let mut commit_key = kdf::derive_commitment_key(shared_secret, snapshot)?;

    let mut message = Vec::with_capacity(32 + 32 + 32 + 16 + ciphertext.len());
    message.extend_from_slice(&proof.nonce);
    message.extend_from_slice(&proof.prev_mac);
    message.extend_from_slice(&snapshot.bytes);
    message.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
    message.extend_from_slice(ciphertext);

    let verified = kk_mix::kk_mac_verify_with_entropy(
        &commit_key,
        &message,
        &proof.mac,
        &snapshot.bytes,
    );
    commit_key.zeroize();

    if verified {
        Ok(())
    } else {
        Err(KkError::CommitmentMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy;

    // ── Basic commitment tests (preserved) ──

    #[test]
    fn valid_commitment_verifies() {
        let secret = b"test-key";
        let snap = entropy::gather().unwrap();
        let ciphertext = b"some ciphertext bytes";

        let commitment = commit(secret, &snap, ciphertext).unwrap();
        verify(secret, &snap, ciphertext, &commitment).unwrap();
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let secret = b"test-key";
        let snap = entropy::gather().unwrap();
        let ciphertext = b"original ciphertext";

        let commitment = commit(secret, &snap, ciphertext).unwrap();

        let tampered = b"tampered ciphertext";
        let result = verify(secret, &snap, tampered, &commitment);
        assert!(result.is_err(), "Tampered ciphertext must fail verification");
    }

    #[test]
    fn wrong_key_fails() {
        let snap = entropy::gather().unwrap();
        let ciphertext = b"test data";

        let commitment = commit(b"correct-key", &snap, ciphertext).unwrap();
        let result = verify(b"wrong-key", &snap, ciphertext, &commitment);
        assert!(result.is_err(), "Wrong shared secret must fail verification");
    }

    // ── Temporal proof tests ──

    #[test]
    fn bound_proof_verifies() {
        let secret = b"test-key";
        let snap = entropy::gather().unwrap();
        let ciphertext = b"bound ciphertext";
        let nonce = generate_challenge().unwrap();

        let proof = commit_bound(secret, &snap, ciphertext, &nonce, &GENESIS_MAC).unwrap();
        verify_bound(
            secret, &snap, ciphertext, &proof, &nonce,
            Duration::from_secs(5),
        ).unwrap();
    }

    #[test]
    fn wrong_nonce_rejected() {
        let secret = b"test-key";
        let snap = entropy::gather().unwrap();
        let ciphertext = b"nonce test";
        let real_nonce = generate_challenge().unwrap();
        let fake_nonce = generate_challenge().unwrap();

        let proof = commit_bound(secret, &snap, ciphertext, &real_nonce, &GENESIS_MAC).unwrap();
        let result = verify_bound(
            secret, &snap, ciphertext, &proof, &fake_nonce,
            Duration::from_secs(5),
        );
        assert!(matches!(result, Err(KkError::StaleNonce)),
            "Wrong nonce must be rejected as StaleNonce");
    }

    #[test]
    fn tampered_ciphertext_fails_bound() {
        let secret = b"test-key";
        let snap = entropy::gather().unwrap();
        let nonce = generate_challenge().unwrap();

        let proof = commit_bound(secret, &snap, b"original", &nonce, &GENESIS_MAC).unwrap();
        let result = verify_bound(
            secret, &snap, b"tampered", &proof, &nonce,
            Duration::from_secs(5),
        );
        assert!(result.is_err(), "Tampered ciphertext must fail bound verification");
    }

    #[test]
    fn epoch_drift_rejected() {
        let secret = b"test-key";
        let ciphertext = b"epoch test";
        let nonce = generate_challenge().unwrap();

        // Create a snapshot with a timestamp far in the past
        let real_snap = entropy::gather().unwrap();
        let old_snap = EntropySnapshot {
            bytes: real_snap.bytes,
            timestamp_nanos: 1_000_000_000_000_000_000, // ~2001
        };

        let proof = commit_bound(secret, &old_snap, ciphertext, &nonce, &GENESIS_MAC).unwrap();
        let result = verify_bound(
            secret, &old_snap, ciphertext, &proof, &nonce,
            Duration::from_secs(5),
        );
        assert!(matches!(result, Err(KkError::EpochDrift { .. })),
            "Ancient timestamp must be rejected as EpochDrift");
    }

    #[test]
    fn chain_ordering() {
        let secret = b"chain-key";
        let nonce1 = generate_challenge().unwrap();
        let nonce2 = generate_challenge().unwrap();

        // Proof 1 (genesis)
        let snap1 = entropy::gather().unwrap();
        let ct1 = b"message one";
        let proof1 = commit_bound(secret, &snap1, ct1, &nonce1, &GENESIS_MAC).unwrap();
        verify_bound(secret, &snap1, ct1, &proof1, &nonce1, Duration::from_secs(5)).unwrap();

        // Proof 2 (chained to proof 1)
        let snap2 = entropy::gather().unwrap();
        let ct2 = b"message two";
        let proof2 = commit_bound(secret, &snap2, ct2, &nonce2, &proof1.mac).unwrap();
        verify_bound(secret, &snap2, ct2, &proof2, &nonce2, Duration::from_secs(5)).unwrap();

        // Verify the chain link
        assert_eq!(proof2.prev_mac, proof1.mac,
            "Proof 2 must reference Proof 1's MAC");
        assert_eq!(proof1.prev_mac, GENESIS_MAC,
            "Proof 1 must reference genesis");
    }

    #[test]
    fn proof_serde_roundtrip() {
        let secret = b"serde-key";
        let snap = entropy::gather().unwrap();
        let nonce = generate_challenge().unwrap();

        let proof = commit_bound(secret, &snap, b"serde test", &nonce, &GENESIS_MAC).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), TemporalProof::BYTES);

        let restored = TemporalProof::from_bytes(&bytes).unwrap();
        assert_eq!(restored.mac, proof.mac);
        assert_eq!(restored.nonce, proof.nonce);
        assert_eq!(restored.prev_mac, proof.prev_mac);
    }

    #[test]
    fn wrong_prev_mac_fails() {
        let secret = b"chain-key";
        let snap = entropy::gather().unwrap();
        let nonce = generate_challenge().unwrap();
        let ciphertext = b"chain integrity";

        // Create with one prev_mac
        let proof = commit_bound(secret, &snap, ciphertext, &nonce, &GENESIS_MAC).unwrap();

        // Forge a different prev_mac in the proof
        let mut forged = proof.clone();
        forged.prev_mac = [0xFF; 32];

        // MAC check will fail because the message includes prev_mac
        let result = verify_bound(
            secret, &snap, ciphertext, &forged, &nonce,
            Duration::from_secs(5),
        );
        assert!(result.is_err(), "Forged prev_mac must fail MAC verification");
    }
}
