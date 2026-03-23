// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! GPU-accelerated KK permutation via wgpu compute shaders.
//!
//! The entire KK permutation (MFR, DDR, quintet-round, round constants,
//! intra-round re-keying) runs on the GPU. Since WGSL lacks native u64,
//! all 64-bit arithmetic is emulated via `vec2<u32>` pairs.
//!
//! # When to use GPU
//!
//! GPU acceleration pays off only for **large batches** of independent
//! permutations (≥1024). Single operations are faster on the CPU due to
//! PCIe transfer overhead (~200 μs round-trip for small buffers).
//!
//! The sweet spot is `kk_kdf_batch_gpu()`: CPU absorbs the shared
//! key/salt prefix, then the GPU squeezes N independent KDF streams
//! in parallel.
//!
//! # Example
//!
//! ```rust,no_run
//! use kk_crypto::gpu::GpuAccelerator;
//!
//! let gpu = GpuAccelerator::new().expect("no GPU available");
//! println!("GPU: {}", gpu.device_name());
//!
//! let key = b"shared-secret";
//! let salt = b"entropy-salt";
//! let infos: Vec<&[u8]> = (0..4096u32)
//!     .map(|i| i.to_le_bytes())
//!     .collect::<Vec<_>>()
//!     .iter()
//!     .map(|b| b.as_slice())
//!     .collect();
//! let results = gpu.kk_kdf_batch(key, salt, &infos, 32);
//! ```

use crate::error::KkError;
use crate::kk_mix::{
    KkSponge, KkState, KDF_SQUEEZE_ROUNDS, RATE_BYTES, RATE_WORDS, STATE_WORDS,
};
use wgpu::util::DeviceExt;
use zeroize::Zeroize;

/// GPU accelerator for batch KK permutations.
///
/// Holds the wgpu device, queue, and compiled compute pipeline.
/// Create once and reuse for multiple batch operations.
pub struct GpuAccelerator {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    adapter_name: String,
}

/// Uniform buffer layout matching the WGSL `Params` struct.
#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct GpuParams {
    rounds: u32,
    num_states: u32,
}

impl GpuAccelerator {
    /// Create a new GPU accelerator, auto-detecting the best available GPU.
    ///
    /// Returns `Err(KkError::GpuError)` if no suitable GPU is found.
    pub fn new() -> Result<Self, KkError> {
        pollster::block_on(Self::new_async())
    }

    async fn new_async() -> Result<Self, KkError> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .ok_or_else(|| KkError::GpuError("no GPU adapter found".into()))?;

        let adapter_name = adapter.get_info().name.clone();

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("kk-crypto-gpu"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits {
                    max_storage_buffer_binding_size: 256 * 1024 * 1024, // 256 MiB
                    max_buffer_size: 256 * 1024 * 1024,
                    ..wgpu::Limits::default()
                },
                memory_hints: wgpu::MemoryHints::Performance,
            }, None)
            .await
            .map_err(|e| KkError::GpuError(format!("device request failed: {e}")))?;

        let shader_source = include_str!("kk_permute.wgsl");
        let shader_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("kk_permute"),
            source: wgpu::ShaderSource::Wgsl(shader_source.into()),
        });

        let bind_group_layout =
            device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
                label: Some("kk_permute_bgl"),
                entries: &[
                    // binding 0: states (read_write storage)
                    wgpu::BindGroupLayoutEntry {
                        binding: 0,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    // binding 1: rotations (read-only storage)
                    wgpu::BindGroupLayoutEntry {
                        binding: 1,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                    // binding 2: params (uniform)
                    wgpu::BindGroupLayoutEntry {
                        binding: 2,
                        visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Uniform,
                            has_dynamic_offset: false,
                            min_binding_size: None,
                        },
                        count: None,
                    },
                ],
            });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("kk_permute_pl"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("kk_permute_pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: Some("kk_permute_kernel"),
            compilation_options: Default::default(),
            cache: None,
        });

        Ok(Self {
            device,
            queue,
            pipeline,
            bind_group_layout,
            adapter_name,
        })
    }

    /// The name of the GPU adapter in use.
    pub fn device_name(&self) -> &str {
        &self.adapter_name
    }

    /// Run N independent KK permutations on the GPU.
    ///
    /// Each state is 25 × u64 (200 bytes). The GPU processes all N states
    /// in parallel using one dispatch.
    ///
    /// `rounds`: number of permutation rounds (32 for full, 20 for KDF squeeze).
    pub fn permute_batch(
        &self,
        states: &mut [KkState],
        rotations: &[[u32; 2]; 15],
        rounds: usize,
    ) {
        if states.is_empty() {
            return;
        }
        pollster::block_on(self.permute_batch_async(states, rotations, rounds));
    }

    async fn permute_batch_async(
        &self,
        states: &mut [KkState],
        rotations: &[[u32; 2]; 15],
        rounds: usize,
    ) {
        let n = states.len();

        // Pack states: each u64 → 2 × u32 (lo, hi), little-endian
        let mut state_data: Vec<u32> = Vec::with_capacity(n * STATE_WORDS * 2);
        for state in states.iter() {
            for &word in state.iter() {
                state_data.push(word as u32);
                state_data.push((word >> 32) as u32);
            }
        }

        // Pack rotations: 15 pairs → 30 u32s
        let mut rot_data = [0u32; 30];
        for (i, pair) in rotations.iter().enumerate() {
            rot_data[i * 2] = pair[0];
            rot_data[i * 2 + 1] = pair[1];
        }

        let params = GpuParams {
            rounds: rounds as u32,
            num_states: n as u32,
        };

        // Create GPU buffers
        let state_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("states"),
            contents: bytemuck::cast_slice(&state_data),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        });

        let rot_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("rotations"),
            contents: bytemuck::cast_slice(&rot_data),
            usage: wgpu::BufferUsages::STORAGE,
        });

        let params_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("params"),
            contents: bytemuck::bytes_of(&params),
            usage: wgpu::BufferUsages::UNIFORM,
        });

        let readback_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("readback"),
            size: (state_data.len() * 4) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });

        // Create bind group
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("kk_bg"),
            layout: &self.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: state_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: rot_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: params_buf.as_entire_binding(),
                },
            ],
        });

        // Dispatch
        let workgroup_size = 64u32;
        let num_workgroups = (n as u32 + workgroup_size - 1) / workgroup_size;

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("kk_enc"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("kk_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(num_workgroups, 1, 1);
        }

        encoder.copy_buffer_to_buffer(
            &state_buf,
            0,
            &readback_buf,
            0,
            (state_data.len() * 4) as u64,
        );

        self.queue.submit(std::iter::once(encoder.finish()));

        // Map readback buffer and extract results
        let (tx, rx) = std::sync::mpsc::channel();
        readback_buf
            .slice(..)
            .map_async(wgpu::MapMode::Read, move |result| {
                let _ = tx.send(result);
            });
        self.device.poll(wgpu::Maintain::Wait);
        rx.recv()
            .expect("GPU readback channel closed")
            .expect("GPU readback mapping failed");

        {
            let data = readback_buf.slice(..).get_mapped_range();
            let result_u32s: &[u32] = bytemuck::cast_slice(&data);

            for (si, state) in states.iter_mut().enumerate() {
                let base = si * STATE_WORDS * 2;
                for w in 0..STATE_WORDS {
                    let lo = result_u32s[base + w * 2] as u64;
                    let hi = result_u32s[base + w * 2 + 1] as u64;
                    state[w] = lo | (hi << 32);
                }
            }
        }
        readback_buf.unmap();

        // Zeroize host-side copy
        state_data.zeroize();
    }

    /// Batch KDF: derive key material for N different `info` values on the GPU.
    ///
    /// Produces the **same output** as calling `kk_kdf()` N times with the same
    /// `key`/`salt` but different `info` strings. The CPU absorbs the shared
    /// prefix, then the GPU runs all squeeze permutations in parallel.
    ///
    /// For N ≥ 1024 this is significantly faster than CPU-only, even with
    /// the u64 emulation overhead, because 10K+ GPU threads run simultaneously.
    ///
    /// # Security Note
    ///
    /// Each returned `Vec<u8>` contains sensitive key material.
    /// Call `.zeroize()` on each vector when you are done.
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
            self.permute_batch(&mut raw_states, &rotations, KDF_SQUEEZE_ROUNDS);
        }

        raw_states.zeroize();
        outputs
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
