//! Temporal commitment scheme for KK.
//!
//! Creates and verifies a cryptographic commitment that binds
//! the ciphertext to the exact entropic moment of its creation.
//!
//! The commitment proves:
//!   - The entropy snapshot ε was used with this shared secret
//!   - The ciphertext was produced at this specific moment
//!   - Any tampering with ε or the ciphertext is detectable
//!
//! commitment = KK-MAC(commitment_key, ε.bytes || ε.timestamp || ciphertext)
//!
//! Built entirely from the KK permutation  - no HMAC, no SHA-256.

use crate::entropy::EntropySnapshot;
use crate::error::{KkError, Result};
use crate::kdf;
use crate::kk_mix;

/// A temporal commitment binding ciphertext to its entropic moment.
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

/// Create a temporal commitment over the entropy snapshot and ciphertext.
///
/// This binds the exact entropic moment to the produced ciphertext.
/// The commitment key is derived from the shared secret and entropy,
/// so only parties with the shared secret can verify.
pub fn commit(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    ciphertext: &[u8],
) -> Result<TemporalCommitment> {
    let commit_key = kdf::derive_commitment_key(shared_secret, snapshot)?;

    // Build the message: entropy bytes || timestamp || ciphertext
    let mut message = Vec::with_capacity(32 + 16 + ciphertext.len());
    message.extend_from_slice(&snapshot.bytes);
    message.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
    message.extend_from_slice(ciphertext);

    let mac_bytes = kk_mix::kk_mac(&commit_key, &message);

    Ok(TemporalCommitment { mac: mac_bytes })
}

/// Verify a temporal commitment.
///
/// Returns Ok(()) if the commitment is valid, meaning:
///   - The entropy snapshot matches what was used during encoding
///   - The ciphertext hasn't been tampered with
///   - The shared secret is correct
///
/// # Side-Channel Safety
/// Uses constant-time comparison internally (byte-by-byte OR accumulation)
/// to prevent timing-based side-channel attacks.
pub fn verify(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    ciphertext: &[u8],
    commitment: &TemporalCommitment,
) -> Result<()> {
    let commit_key = kdf::derive_commitment_key(shared_secret, snapshot)?;

    // Build the same message as commit()
    let mut message = Vec::with_capacity(32 + 16 + ciphertext.len());
    message.extend_from_slice(&snapshot.bytes);
    message.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
    message.extend_from_slice(ciphertext);

    if kk_mix::kk_mac_verify(&commit_key, &message, &commitment.mac) {
        Ok(())
    } else {
        Err(KkError::CommitmentMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy;

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
}
