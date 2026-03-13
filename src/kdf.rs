// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

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

/// Derives per-symbol key streams for 8 consecutive chunk indices simultaneously.
///
/// Same result as calling [`derive_symbol_key`] 8 times with consecutive
/// indices starting at `base_index`, but uses AVX-512 batch KDF when available.
pub fn derive_symbol_key_batch(
    shared_secret: &[u8],
    snapshot: &EntropySnapshot,
    base_index: u64,
    output_len: usize,
) -> Result<[Vec<u8>; 8]> {
    let infos_raw: [Vec<u8>; 8] = core::array::from_fn(|i| {
        let mut info = Vec::with_capacity(10 + 8 + 8);
        info.extend_from_slice(b"KK-sym-v1\0");
        info.extend_from_slice(&(base_index + i as u64).to_le_bytes());
        info.extend_from_slice(&snapshot.timestamp_nanos.to_le_bytes());
        info
    });
    let infos: [&[u8]; 8] = core::array::from_fn(|i| infos_raw[i].as_slice());

    let output = kk_mix::kk_kdf_batch_8(shared_secret, &snapshot.bytes, infos, output_len);
    Ok(output)
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

    #[test]
    fn batch_matches_individual_derive() {
        let secret = b"batch-derive-secret";
        let snap = entropy::gather().unwrap();
        let output_len = 4096;

        let batch = derive_symbol_key_batch(secret, &snap, 0, output_len).unwrap();

        for i in 0..8u64 {
            let scalar = derive_symbol_key(secret, &snap, i, output_len).unwrap();
            assert_eq!(
                batch[i as usize], scalar,
                "Batch derive lane {i} diverged from scalar derive_symbol_key"
            );
        }
    }
}
