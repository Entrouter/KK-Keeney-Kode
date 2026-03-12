//! KK Codec  - The core encoding/decoding primitive.
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
//! is different  - that moment is gone, unrepeatable, unrecoverable.
//!
//! ## Encoding Flow
//!
//! ```text
//! plaintext bytes → for each byte[i]:
//!   key_i = HKDF(shared_secret, salt=ε, info=i||timestamp)
//!   cipher_i = byte[i] ⊕ key_i
//! → ciphertext
//! ```
//!
//! ## Decoding Flow
//!
//! ```text
//! ciphertext + ε → for each byte[i]:
//!   key_i = HKDF(shared_secret, salt=ε, info=i||timestamp)  // SAME derivation
//!   plain_i = cipher_i ⊕ key_i                               // XOR is its own inverse
//! → plaintext
//! ```

use zeroize::Zeroize;

use crate::entropy::{self, EntropySnapshot};
use crate::error::{KkError, Result};
use crate::kdf;
use crate::temporal::{self, TemporalCommitment};

/// The number of plaintext bytes processed per HKDF derivation.
/// Larger chunks = fewer HKDF calls = better performance.
/// Each chunk still gets a unique key derived from its position.
const CHUNK_SIZE: usize = 64;

/// A KK-encoded packet: everything the receiver needs to decode.
///
/// Contains:
///   - The ciphertext (XOR of plaintext with per-symbol key stream)
///   - The entropy snapshot ε (the unrepeatable moment)
///   - Temporal commitment (proves integrity of ε + ciphertext binding)
#[derive(Clone)]
pub struct KkPacket {
    /// The encoded bytes  - symbol values transmuted by entropy
    pub ciphertext: Vec<u8>,
    /// The entropy snapshot  - the captured moment
    pub entropy_snapshot: EntropySnapshot,
    /// Temporal commitment  - binds ciphertext to its entropic moment
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

/// Encode plaintext using the KK primitive.
///
/// This is the fundamental KK operation:
///   1. Capture entropy from the universe at this exact moment
///   2. For each symbol, derive a unique key from (secret, ε, position)
///   3. XOR the symbol with its key  - the symbol's value is now
///      a function of the universe at the instant it was born
///   4. Create a temporal commitment binding everything together
///
/// The returned KkPacket contains everything the receiver needs.
pub fn encode(shared_secret: &[u8], plaintext: &[u8]) -> Result<KkPacket> {
    if plaintext.is_empty() {
        return Err(KkError::EmptyInput);
    }

    // Step 1: Capture the entropic moment  - this instant will never exist again
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
    // Step 1: Verify temporal commitment  - is this packet intact?
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

/// Internal: XOR input with the KK-derived keystream.
///
/// Processes in chunks for efficiency. Each chunk position gets
/// a unique key derivation, ensuring per-symbol independence.
fn xor_with_keystream(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    input: &[u8],
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());

    for (chunk_idx, chunk) in input.chunks(CHUNK_SIZE).enumerate() {
        // Derive key material for this chunk position
        let mut key_bytes = kdf::derive_symbol_key(
            shared_secret,
            snapshot,
            chunk_idx as u64,
            chunk.len(),
        )?;

        // XOR: symbol value becomes a function of the entropic moment
        for (i, &byte) in chunk.iter().enumerate() {
            output.push(byte ^ key_bytes[i]);
        }

        key_bytes.zeroize();
    }

    Ok(output)
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
}
