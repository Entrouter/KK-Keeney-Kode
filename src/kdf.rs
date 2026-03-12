//! Key derivation for KK.
//!
//! Uses the KK-Sponge-KDF to derive per-symbol keys from:
//!   - The shared secret (what sender and receiver both know)
//!   - The entropy snapshot ε (the unrepeatable moment)
//!   - The symbol index (position in message)
//!
//! This ensures every symbol in every message gets a unique,
//! cryptographically independent key stream.
//!
//! Built entirely from the KK permutation  - no HKDF, no SHA-256.

use zeroize::Zeroize;

use crate::entropy::EntropySnapshot;
use crate::error::Result;
use crate::kk_mix;

/// Derives a per-symbol key stream.
///
/// For symbol at position `index` in a message:
///   key_i = KK-KDF(
///     key  = shared_secret,
///     salt = ε.bytes,
///     info = "KK-sym-v1" || index || ε.timestamp_nanos
///   )
///
/// Each symbol gets its own unique key  - the alphabet is fluid.
pub fn derive_symbol_key(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    symbol_index: u64,
    output_len: usize,
) -> Result<Vec<u8>> {
    // Build info: domain || index || temporal mark
    let mut info = Vec::with_capacity(10 + 8 + 16);
    info.extend_from_slice(b"KK-sym-v1\0");
    info.extend_from_slice(&symbol_index.to_le_bytes());
    info.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());

    let output = kk_mix::kk_kdf(shared_secret, &snapshot.bytes, &info, output_len);

    info.zeroize();
    Ok(output)
}

/// Derives the temporal commitment key used for MAC verification.
pub fn derive_commitment_key(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
) -> Result<Vec<u8>> {
    let key = kk_mix::kk_kdf(shared_secret, &snapshot.bytes, b"KK-commit-v1", 32);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy;

    #[test]
    fn same_index_different_entropy_different_key() {
        let secret = b"shared-secret";
        let snap1 = entropy::gather().unwrap();
        let snap2 = entropy::gather().unwrap();

        let k1 = derive_symbol_key(secret, &snap1, 0, 32).unwrap();
        let k2 = derive_symbol_key(secret, &snap2, 0, 32).unwrap();
        assert_ne!(k1, k2, "Different entropic moments must yield different keys");
    }

    #[test]
    fn different_index_same_entropy_different_key() {
        let secret = b"shared-secret";
        let snap = entropy::gather().unwrap();

        let k0 = derive_symbol_key(secret, &snap, 0, 32).unwrap();
        let k1 = derive_symbol_key(secret, &snap, 1, 32).unwrap();
        assert_ne!(k0, k1, "Different symbol positions must yield different keys");
    }

    #[test]
    fn deterministic_with_same_inputs() {
        let secret = b"shared-secret";
        let snap = entropy::gather().unwrap();

        let k1 = derive_symbol_key(secret, &snap, 42, 16).unwrap();
        let k2 = derive_symbol_key(secret, &snap, 42, 16).unwrap();
        assert_eq!(k1, k2, "Same inputs must produce same key (deterministic derivation)");
    }
}
