// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! KK-RNG: A deterministic random bit generator built entirely from the KK sponge.
//!
//! Replaces any need for an external DRBG. Seeded once, it produces an
//! unlimited stream of cryptographically independent pseudorandom bytes.
//!
//! ## Construction
//!
//! ```text
//! state₀ = KK-Hash(seed)
//! (output_i, state_{i+1}) = KK-KDF(state_i, counter_i, "KK-RNG", len)
//! ```
//!
//! Each call to `next_bytes` derives output material and ratchets the
//! internal state forward, so past outputs cannot be recovered even if
//! the current state is compromised (forward secrecy of output stream).
//!
//! ## Example
//!
//! ```rust
//! use kk_crypto::rng::KkRng;
//!
//! let mut rng = KkRng::new(b"my-seed-material");
//! let random_bytes = rng.next_bytes(64);
//! assert_eq!(random_bytes.len(), 64);
//!
//! // Deterministic: same seed → same output
//! let mut rng2 = KkRng::new(b"my-seed-material");
//! assert_eq!(rng2.next_bytes(64), random_bytes);
//! ```

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kk_mix;

/// A deterministic random bit generator built on the KK sponge.
///
/// Internally holds a 256-bit state and a 64-bit counter.
/// Every call to [`next_bytes`](KkRng::next_bytes) ratchets
/// both the counter and state forward.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KkRng {
    state: [u8; 32],
    counter: u64,
}

impl KkRng {
    /// Create a new KK-RNG from arbitrary seed material.
    ///
    /// The seed is hashed through KK-Hash to produce the initial state,
    /// so any length of seed is acceptable (though ≥ 32 bytes is recommended).
    pub fn new(seed: &[u8]) -> Self {
        Self {
            state: kk_mix::kk_hash(seed),
            counter: 0,
        }
    }

    /// Derive `len` pseudorandom bytes and ratchet the state forward.
    ///
    /// Each call is domain-separated by the internal counter, so
    /// successive calls with the same `len` produce different output.
    ///
    /// The internal state is ratcheted after each call: even if an
    /// attacker obtains the output, they cannot recover the state
    /// that produced it.
    pub fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        // Derive output + 32 bytes of new state material in one KDF call
        let mut combined = kk_mix::kk_kdf(
            &self.state,
            &self.counter.to_le_bytes(),
            b"KK-RNG",
            len + 32,
        );

        // Split: first `len` bytes are output, last 32 bytes ratchet state
        let output = combined[..len].to_vec();
        self.state.copy_from_slice(&combined[len..len + 32]);
        self.counter = self.counter.wrapping_add(1);

        combined.zeroize();
        output
    }

    /// Fill a mutable slice with pseudorandom bytes.
    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        let bytes = self.next_bytes(dest.len());
        dest.copy_from_slice(&bytes);
    }

    /// Generate a pseudorandom `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let bytes = self.next_bytes(8);
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }

    /// Reseed the RNG with additional entropy, mixing it into the current state.
    ///
    /// This is useful for periodic reseeding from an OS entropy source.
    pub fn reseed(&mut self, additional_seed: &[u8]) {
        let mut material = Vec::with_capacity(32 + additional_seed.len());
        material.extend_from_slice(&self.state);
        material.extend_from_slice(additional_seed);
        self.state = kk_mix::kk_hash(&material);
        self.counter = 0;
        material.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────
//  KkRngPool - Parallel RNG with N independent streams
// ─────────────────────────────────────────────────────────────────

#[cfg(feature = "std")]
use std::sync::{atomic::{AtomicUsize, Ordering}, Mutex};

/// A pool of independent [`KkRng`] instances for parallel random byte generation.
///
/// Each generator is seeded with `seed || index` (domain-separated), so all
/// streams are cryptographically independent. The pool dispatches via
/// round-robin with interior mutability (`Mutex` per generator).
///
/// ## Example
///
/// ```rust
/// use kk_crypto::rng::KkRngPool;
///
/// let pool = KkRngPool::new(b"my-seed", 4);
/// let bytes = pool.next_bytes(128);
/// assert_eq!(bytes.len(), 128);
///
/// // Parallel fill - splits work across all generators
/// let mut buf = vec![0u8; 4096];
/// pool.fill_bytes_parallel(&mut buf);
/// assert!(buf.iter().any(|&b| b != 0));
/// ```
#[cfg(feature = "std")]
pub struct KkRngPool {
    generators: Vec<Mutex<KkRng>>,
    next: AtomicUsize,
}

#[cfg(feature = "std")]
impl KkRngPool {
    /// Create a pool of `num_generators` independent RNG instances.
    ///
    /// Each generator is seeded with `seed || generator_index` (little-endian u64),
    /// providing domain separation between streams.
    ///
    /// # Panics
    /// Panics if `num_generators` is 0.
    pub fn new(seed: &[u8], num_generators: usize) -> Self {
        assert!(num_generators > 0, "KkRngPool requires at least 1 generator");
        let generators = (0..num_generators)
            .map(|i| {
                let mut domain_seed = Vec::with_capacity(seed.len() + 8);
                domain_seed.extend_from_slice(seed);
                domain_seed.extend_from_slice(&(i as u64).to_le_bytes());
                let rng = KkRng::new(&domain_seed);
                domain_seed.zeroize();
                Mutex::new(rng)
            })
            .collect();

        Self {
            generators,
            next: AtomicUsize::new(0),
        }
    }

    /// Number of generators in the pool.
    pub fn num_generators(&self) -> usize {
        self.generators.len()
    }

    /// Generate `len` random bytes using the next generator in round-robin order.
    pub fn next_bytes(&self, len: usize) -> Vec<u8> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.generators.len();
        let mut gen = self.generators[idx].lock().expect("KkRngPool: poisoned mutex");
        gen.next_bytes(len)
    }

    /// Fill `dest` by splitting it across all generators in parallel via Rayon.
    ///
    /// Each generator fills an approximately equal chunk. The output is
    /// deterministic for a given seed and `dest.len()` (assuming no other
    /// concurrent calls to the same pool, which would advance generator state).
    pub fn fill_bytes_parallel(&self, dest: &mut [u8]) {
        use rayon::prelude::*;

        if dest.is_empty() {
            return;
        }

        let n = self.generators.len();
        let chunk_size = dest.len().div_ceil(n);

        dest.chunks_mut(chunk_size)
            .enumerate()
            .collect::<Vec<_>>()
            .into_par_iter()
            .for_each(|(i, chunk)| {
                let mut gen = self.generators[i].lock().expect("KkRngPool: poisoned mutex");
                gen.fill_bytes(chunk);
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let mut rng1 = KkRng::new(b"test-seed-12345");
        let mut rng2 = KkRng::new(b"test-seed-12345");
        assert_eq!(rng1.next_bytes(64), rng2.next_bytes(64));
        assert_eq!(rng1.next_bytes(32), rng2.next_bytes(32));
    }

    #[test]
    fn different_seeds_differ() {
        let mut rng1 = KkRng::new(b"seed-alpha");
        let mut rng2 = KkRng::new(b"seed-beta");
        assert_ne!(rng1.next_bytes(32), rng2.next_bytes(32));
    }

    #[test]
    fn successive_calls_differ() {
        let mut rng = KkRng::new(b"counter-test");
        let a = rng.next_bytes(32);
        let b = rng.next_bytes(32);
        assert_ne!(a, b);
    }

    #[test]
    fn fill_bytes_matches_next_bytes() {
        let mut rng1 = KkRng::new(b"fill-test");
        let mut rng2 = KkRng::new(b"fill-test");
        let expected = rng1.next_bytes(48);
        let mut buf = [0u8; 48];
        rng2.fill_bytes(&mut buf);
        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn next_u64_deterministic() {
        let mut rng1 = KkRng::new(b"u64-test");
        let mut rng2 = KkRng::new(b"u64-test");
        assert_eq!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn reseed_changes_output() {
        let mut rng1 = KkRng::new(b"reseed-test");
        let mut rng2 = KkRng::new(b"reseed-test");
        rng1.reseed(b"extra-entropy");
        // After reseeding, output diverges
        assert_ne!(rng1.next_bytes(32), rng2.next_bytes(32));
    }

    #[test]
    fn large_output() {
        let mut rng = KkRng::new(b"large-test");
        let out = rng.next_bytes(1024);
        assert_eq!(out.len(), 1024);
        // Should not be all zeros
        assert!(out.iter().any(|&b| b != 0));
    }

    #[test]
    fn zero_length_output() {
        let mut rng = KkRng::new(b"zero-test");
        let out = rng.next_bytes(0);
        assert!(out.is_empty());
    }

    // ── KkRngPool tests ──────────────────────────────────────────

    #[cfg(feature = "std")]
    mod pool_tests {
        use super::super::KkRngPool;

        #[test]
        fn pool_deterministic() {
            let pool1 = KkRngPool::new(b"pool-seed", 4);
            let pool2 = KkRngPool::new(b"pool-seed", 4);
            // Same pool, same sequence of calls → same output
            for _ in 0..8 {
                assert_eq!(pool1.next_bytes(64), pool2.next_bytes(64));
            }
        }

        #[test]
        fn pool_domain_separation() {
            // Generator 0 and generator 1 should produce different streams
            let pool_a = KkRngPool::new(b"sep-seed", 2);
            let pool_b = KkRngPool::new(b"sep-seed", 2);
            let from_gen0 = pool_a.next_bytes(32); // hits generator 0
            let _ = pool_b.next_bytes(32);         // hits generator 0 (discard)
            let from_gen1 = pool_b.next_bytes(32); // hits generator 1
            assert_ne!(from_gen0, from_gen1);
        }

        #[test]
        fn pool_round_robin() {
            let pool = KkRngPool::new(b"rr-seed", 3);
            // 6 calls should cycle through generators 0,1,2,0,1,2
            // Calls 0 and 3 hit the same generator, so sequential output differs
            // (each call advances that generator's counter)
            let a0 = pool.next_bytes(32);
            let _a1 = pool.next_bytes(32);
            let _a2 = pool.next_bytes(32);
            let a3 = pool.next_bytes(32); // same generator as a0, but advanced
            assert_ne!(a0, a3);
        }

        #[test]
        fn pool_single_generator() {
            // Pool with 1 generator should behave identically to a bare KkRng
            // seeded with seed||0u64
            use super::super::KkRng;
            let pool = KkRngPool::new(b"single", 1);
            let mut expected_seed = b"single".to_vec();
            expected_seed.extend_from_slice(&0u64.to_le_bytes());
            let mut bare = KkRng::new(&expected_seed);
            for _ in 0..4 {
                assert_eq!(pool.next_bytes(128), bare.next_bytes(128));
            }
        }

        #[test]
        fn fill_bytes_parallel_deterministic() {
            let pool1 = KkRngPool::new(b"fill-par", 4);
            let pool2 = KkRngPool::new(b"fill-par", 4);
            let mut buf1 = vec![0u8; 8192];
            let mut buf2 = vec![0u8; 8192];
            pool1.fill_bytes_parallel(&mut buf1);
            pool2.fill_bytes_parallel(&mut buf2);
            assert_eq!(buf1, buf2);
        }

        #[test]
        fn fill_bytes_parallel_nonzero() {
            let pool = KkRngPool::new(b"nz-par", 4);
            let mut buf = vec![0u8; 4096];
            pool.fill_bytes_parallel(&mut buf);
            assert!(buf.iter().any(|&b| b != 0));
        }

        #[test]
        fn fill_bytes_parallel_empty() {
            let pool = KkRngPool::new(b"empty-par", 4);
            let mut buf: Vec<u8> = vec![];
            pool.fill_bytes_parallel(&mut buf); // should not panic
        }

        #[test]
        fn num_generators_correct() {
            for n in [1, 4, 16, 32] {
                let pool = KkRngPool::new(b"count", n);
                assert_eq!(pool.num_generators(), n);
            }
        }

        #[test]
        #[should_panic(expected = "at least 1")]
        fn pool_zero_generators_panics() {
            let _ = KkRngPool::new(b"zero", 0);
        }
    }
}
