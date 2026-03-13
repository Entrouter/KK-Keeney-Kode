// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

//! Multi-source entropy collection for KK.
//!
//! Gathers entropy from multiple independent sources and mixes them
//! into a single high-quality entropy snapshot. This snapshot represents
//! the "universal entropy at the moment of creation"  - the ε in KK(S) = S^ε.
//!
//! Sources:
//!   1. OS CSPRNG (CryptGenRandom / getrandom / urandom)
//!   2. High-resolution timestamp (nanosecond precision)
//!   3. CPU timestamp counter (rdtsc / equivalent)
//!   4. Thread scheduling jitter (measured timing noise)
//!
//! All mixing is done with KK-Mix  - no SHA-256, no HKDF.

use rand::RngCore;
use zeroize::Zeroize;

use crate::error::{KkError, Result};
use crate::kk_mix;

/// Size of the final entropy snapshot in bytes (256 bits).
pub const ENTROPY_SNAPSHOT_SIZE: usize = 32;

/// A captured moment of universal entropy  - unrepeatable, unrecoverable.
#[derive(Clone)]
pub struct EntropySnapshot {
    /// The mixed entropy bytes  - the ε in KK(S) = S^ε
    pub bytes: [u8; ENTROPY_SNAPSHOT_SIZE],
    /// High-resolution timestamp at moment of capture (nanos since epoch)
    pub timestamp_nanos: u128,
}

impl Drop for EntropySnapshot {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl EntropySnapshot {
    /// Serialize the snapshot for transmission alongside ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENTROPY_SNAPSHOT_SIZE + 16);
        out.extend_from_slice(&self.bytes);
        out.extend_from_slice(&self.timestamp_nanos.to_le_bytes());
        out
    }

    /// Deserialize an entropy snapshot from transmitted bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < ENTROPY_SNAPSHOT_SIZE + 16 {
            return Err(KkError::InvalidPacket(
                "entropy snapshot too short".into(),
            ));
        }
        let mut bytes = [0u8; ENTROPY_SNAPSHOT_SIZE];
        bytes.copy_from_slice(&data[..ENTROPY_SNAPSHOT_SIZE]);
        let timestamp_nanos = u128::from_le_bytes(
            data[ENTROPY_SNAPSHOT_SIZE..ENTROPY_SNAPSHOT_SIZE + 16]
                .try_into()
                .map_err(|_| KkError::InvalidPacket("bad timestamp bytes".into()))?,
        );
        Ok(Self {
            bytes,
            timestamp_nanos,
        })
    }
}

/// Collect entropy from the OS CSPRNG.
fn source_csprng() -> Result<[u8; 32]> {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| KkError::EntropyFailure(format!("CSPRNG: {e}")))?;
    Ok(buf)
}

/// Collect entropy from high-resolution system clock.
fn source_timestamp() -> (u128, [u8; 16]) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos, nanos.to_le_bytes())
}

/// Collect entropy from CPU timestamp counter / performance counter.
#[cfg(target_arch = "x86_64")]
fn source_cpu_counter() -> [u8; 8] {
    // Read the hardware TSC directly  - this is the real rdtsc value,
    // not a library abstraction that discards the interesting bits.
    let raw: u64 = unsafe { core::arch::x86_64::_rdtsc() };
    // Also fold in the address of a stack variable (ASLR noise)
    let stack_addr = &raw as *const u64 as u64;
    (raw ^ stack_addr).to_le_bytes()
}

/// Fallback for non-x86_64: use high-res timer as proxy.
#[cfg(not(target_arch = "x86_64"))]
fn source_cpu_counter() -> [u8; 8] {
    let now = std::time::Instant::now();
    let raw = now.elapsed().as_nanos() as u64;
    let stack_addr = &raw as *const u64 as u64;
    (raw ^ stack_addr).to_le_bytes()
}

/// Collect scheduling jitter entropy by measuring timing variance
/// across multiple tight loops.
fn source_thread_jitter() -> [u8; 32] {
    // Collect 64 timing measurements as raw bytes
    let mut raw_timings = Vec::with_capacity(64 * 8);
    for _ in 0..64 {
        let start = std::time::Instant::now();
        // Yield to the OS scheduler to create real scheduling jitter,
        // not just instruction-level noise from black_box alone.
        std::thread::yield_now();
        std::hint::black_box(0u64.wrapping_add(1));
        let elapsed = start.elapsed().as_nanos() as u64;
        raw_timings.extend_from_slice(&elapsed.to_le_bytes());
    }
    // Mix all timings through KK-Hash
    kk_mix::kk_hash(&raw_timings)
}

/// Gather all entropy sources and mix them into a single snapshot.
///
/// This is the core of the KK entropy model: at this precise instant,
/// the OS, CPU, scheduler, and hardware all contribute state that will
/// never exist again in the same combination.
pub fn gather() -> Result<EntropySnapshot> {
    // Collect from all sources
    let csprng_bytes = source_csprng()?;
    let (timestamp_nanos, timestamp_bytes) = source_timestamp();
    let cpu_bytes = source_cpu_counter();
    let jitter_bytes = source_thread_jitter();

    // Mix all sources using KK entropy mixing
    let sources: Vec<&[u8]> = vec![
        &csprng_bytes,
        &timestamp_bytes,
        &cpu_bytes,
        &jitter_bytes,
    ];
    let mixed = kk_mix::kk_entropy_mix(&sources, ENTROPY_SNAPSHOT_SIZE);

    let mut output = [0u8; ENTROPY_SNAPSHOT_SIZE];
    output.copy_from_slice(&mixed);

    Ok(EntropySnapshot {
        bytes: output,
        timestamp_nanos,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_snapshots_are_unique() {
        let s1 = gather().unwrap();
        let s2 = gather().unwrap();
        // Two snapshots taken at different moments must differ
        assert_ne!(s1.bytes, s2.bytes, "KK(S) at T₁ ≠ KK(S) at T₂");
    }

    #[test]
    fn snapshot_roundtrip() {
        let snap = gather().unwrap();
        let bytes = snap.to_bytes();
        let restored = EntropySnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(snap.bytes, restored.bytes);
        assert_eq!(snap.timestamp_nanos, restored.timestamp_nanos);
    }
}
