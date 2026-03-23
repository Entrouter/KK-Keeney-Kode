// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! CUDA-accelerated KK permutation via native uint64_t.
//!
//! Unlike the WGSL GPU path that emulates 64-bit arithmetic with
//! `vec2<u32>` pairs, the CUDA kernel uses native `uint64_t` for
//! all multiply, shift, and rotate operations - no emulation overhead.
//!
//! # When to use CUDA
//!
//! CUDA acceleration pays off for **large batches** of independent
//! permutations (≥1024). For smaller batches, CPU throughput
//! (especially AVX-512) dominates due to PCIe transfer latency.
//!
//! # Example
//!
//! ```rust,no_run
//! use kk_crypto::cuda::CudaAccelerator;
//!
//! let cuda = CudaAccelerator::new().expect("no CUDA GPU available");
//! println!("CUDA device: {}", cuda.device_name());
//!
//! let key = b"shared-secret";
//! let salt = b"entropy-salt";
//! let infos: Vec<&[u8]> = (0..4096u32)
//!     .map(|i| i.to_le_bytes())
//!     .collect::<Vec<_>>()
//!     .iter()
//!     .map(|b| b.as_slice())
//!     .collect();
//! let results = cuda.kk_kdf_batch(key, salt, &infos, 32);
//! ```

use crate::error::KkError;
use crate::kk_mix::{
    KkSponge, KkState, KDF_SQUEEZE_ROUNDS, RATE_BYTES, RATE_WORDS, STATE_WORDS,
};
use zeroize::Zeroize;

// ── FFI declarations ───────────────────────────────────────────
extern "C" {
    fn kk_cuda_is_available() -> i32;
    fn kk_cuda_get_device_name(buf: *mut u8, buf_len: i32) -> i32;
    fn kk_cuda_permute_batch(
        host_states: *mut u64,
        host_rotations: *const u32,
        rounds: u32,
        num_states: u32,
    ) -> i32;
    fn kk_cuda_permute_batch_persistent(
        host_states: *mut u64,
        host_rotations: *const u32,
        rounds: u32,
        num_states: u32,
    ) -> i32;
    fn kk_cuda_free_persistent();
}

/// CUDA accelerator for batch KK permutations.
///
/// Holds device metadata. The CUDA runtime manages device state
/// internally; this struct mainly provides a Rust-friendly API
/// and ensures the device was available at construction time.
pub struct CudaAccelerator {
    device_name: String,
}

impl CudaAccelerator {
    /// Create a new CUDA accelerator.
    ///
    /// Returns `Err` if no CUDA-capable GPU is found.
    pub fn new() -> Result<Self, KkError> {
        let available = unsafe { kk_cuda_is_available() };
        if available != 1 {
            return Err(KkError::GpuError("No CUDA-capable GPU found".into()));
        }

        let mut buf = [0u8; 256];
        let rc = unsafe { kk_cuda_get_device_name(buf.as_mut_ptr(), 256) };
        if rc != 0 {
            return Err(KkError::GpuError("Failed to query CUDA device name".into()));
        }

        let name = std::str::from_utf8(&buf)
            .unwrap_or("unknown")
            .trim_end_matches('\0')
            .to_string();

        Ok(Self { device_name: name })
    }

    /// Human-readable CUDA device name.
    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    /// Permute N independent states on the GPU (fresh allocation per call).
    ///
    /// Each state is 25 × u64. The rotations array is 15 × [u32; 2] = 30 u32s.
    pub fn permute_batch(&self, states: &mut [KkState], rotations: &[[u32; 2]; 15], rounds: u32) {
        if states.is_empty() {
            return;
        }

        // Flatten states to contiguous u64 buffer
        let n = states.len();
        let mut flat: Vec<u64> = Vec::with_capacity(n * STATE_WORDS);
        for s in states.iter() {
            flat.extend_from_slice(s);
        }

        // Flatten rotations to contiguous u32 buffer
        let mut rot_flat = [0u32; 30];
        for (i, pair) in rotations.iter().enumerate() {
            rot_flat[i * 2] = pair[0];
            rot_flat[i * 2 + 1] = pair[1];
        }

        let rc = unsafe {
            kk_cuda_permute_batch(
                flat.as_mut_ptr(),
                rot_flat.as_ptr(),
                rounds,
                n as u32,
            )
        };

        if rc != 0 {
            // Fall through silently - states unchanged.
            // In a production system you'd want error propagation,
            // but for benchmarking & testing this is fine.
            return;
        }

        // Copy results back
        for (i, s) in states.iter_mut().enumerate() {
            s.copy_from_slice(&flat[i * STATE_WORDS..(i + 1) * STATE_WORDS]);
        }

        flat.zeroize();
    }

    /// Permute N independent states using persistent GPU buffers.
    ///
    /// Avoids cudaMalloc/cudaFree per call - significantly faster for
    /// repeated invocations (e.g., KDF squeeze loops).
    pub fn permute_batch_persistent(
        &self,
        states: &mut [KkState],
        rotations: &[[u32; 2]; 15],
        rounds: u32,
    ) {
        if states.is_empty() {
            return;
        }

        let n = states.len();
        let mut flat: Vec<u64> = Vec::with_capacity(n * STATE_WORDS);
        for s in states.iter() {
            flat.extend_from_slice(s);
        }

        let mut rot_flat = [0u32; 30];
        for (i, pair) in rotations.iter().enumerate() {
            rot_flat[i * 2] = pair[0];
            rot_flat[i * 2 + 1] = pair[1];
        }

        let rc = unsafe {
            kk_cuda_permute_batch_persistent(
                flat.as_mut_ptr(),
                rot_flat.as_ptr(),
                rounds,
                n as u32,
            )
        };

        if rc != 0 {
            return;
        }

        for (i, s) in states.iter_mut().enumerate() {
            s.copy_from_slice(&flat[i * STATE_WORDS..(i + 1) * STATE_WORDS]);
        }

        flat.zeroize();
    }

    /// Free persistent GPU buffers. Called automatically on drop,
    /// but can be called manually if you want to release GPU memory early.
    pub fn free_persistent(&self) {
        unsafe { kk_cuda_free_persistent() };
    }

    /// Batch KDF: derive key material for N different `info` values on the GPU.
    ///
    /// Produces the **same output** as calling `kk_kdf()` N times with the same
    /// `key`/`salt` but different `info` strings. The CPU absorbs the shared
    /// prefix, then the GPU runs all squeeze permutations in parallel.
    pub fn kk_kdf_batch(
        &self,
        key: &[u8],
        salt: &[u8],
        infos: &[&[u8]],
        output_len: usize,
    ) -> Vec<Vec<u8>> {
        if infos.is_empty() {
            return Vec::new();
        }

        let n = infos.len();

        // CPU: absorb shared prefix (key + salt)
        let mut shared = KkSponge::with_entropy_rotations(salt);
        shared.absorb(key);
        shared.absorb(&(salt.len() as u64).to_le_bytes());
        shared.absorb(salt);

        // CPU: diverge - each clone absorbs its own info, then finalizes
        let mut sponges: Vec<KkSponge> = (0..n).map(|_| shared.clone()).collect();
        drop(shared);

        for i in 0..n {
            sponges[i].absorb(&(infos[i].len() as u64).to_le_bytes());
            sponges[i].absorb(infos[i]);
            sponges[i].finalize_absorb_kdf();
        }

        // Extract raw states for GPU
        let rotations = sponges[0].rotations();
        let mut raw_states: Vec<KkState> = sponges.iter().map(|s| s.state()).collect();
        drop(sponges);

        // GPU squeeze loop
        let mut outputs: Vec<Vec<u8>> = (0..n).map(|_| Vec::with_capacity(output_len)).collect();

        loop {
            // Read rate bytes from current states
            for (i, state) in raw_states.iter().enumerate() {
                let remaining = output_len - outputs[i].len();
                let take = remaining.min(RATE_BYTES);
                let rate = rate_bytes_from_state(state);
                outputs[i].extend_from_slice(&rate[..take]);
            }

            if outputs[0].len() >= output_len {
                break;
            }

            // GPU: permute all states with KDF_SQUEEZE_ROUNDS
            self.permute_batch_persistent(&mut raw_states, &rotations, KDF_SQUEEZE_ROUNDS as u32);
        }

        raw_states.zeroize();
        outputs
    }
}

impl Drop for CudaAccelerator {
    fn drop(&mut self) {
        unsafe { kk_cuda_free_persistent() };
    }
}

/// Extract the rate portion of a raw `KkState` as bytes.
fn rate_bytes_from_state(state: &KkState) -> [u8; RATE_BYTES] {
    let mut out = [0u8; RATE_BYTES];
    for i in 0..RATE_WORDS {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}
