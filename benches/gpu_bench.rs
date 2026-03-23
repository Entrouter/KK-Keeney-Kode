// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! GPU batch KDF benchmark.
//!
//! Run: cargo bench --bench gpu_bench --features gpu

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kk_crypto::gpu::GpuAccelerator;
use kk_crypto::kk_mix::{kk_kdf, kk_kdf_batch_8};

const KEY: &[u8] = b"bench-secret-key-2026";
const SALT: &[u8] = b"bench-salt-entropy";
const OUTPUT_LEN: usize = 32;

fn bench_gpu_kdf_batch(c: &mut Criterion) {
    let gpu = GpuAccelerator::new().expect("GPU required for this benchmark");
    eprintln!("GPU: {}", gpu.device_name());

    let mut group = c.benchmark_group("gpu_kdf_batch");

    for &n in &[64, 256, 1024, 4096, 16384] {
        let infos: Vec<Vec<u8>> = (0..n as u32).map(|i| i.to_le_bytes().to_vec()).collect();
        let info_refs: Vec<&[u8]> = infos.iter().map(|v| v.as_slice()).collect();

        group.throughput(Throughput::Elements(n));

        // GPU batch
        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |b, _| {
            b.iter(|| {
                black_box(gpu.kk_kdf_batch(KEY, SALT, &info_refs, OUTPUT_LEN));
            });
        });

        // CPU sequential (for comparison)
        group.bench_with_input(BenchmarkId::new("cpu_seq", n), &n, |b, _| {
            b.iter(|| {
                let results: Vec<Vec<u8>> = info_refs
                    .iter()
                    .map(|info| kk_kdf(KEY, SALT, info, OUTPUT_LEN))
                    .collect();
                black_box(results);
            });
        });

        // CPU AVX-512 batch-8 (for comparison)
        if n >= 8 {
            group.bench_with_input(BenchmarkId::new("cpu_avx512_batch8", n), &n, |b, _| {
                b.iter(|| {
                    let mut results = Vec::with_capacity(n as usize);
                    for chunk in info_refs.chunks(8) {
                        if chunk.len() == 8 {
                            let batch: [&[u8]; 8] = [
                                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5],
                                chunk[6], chunk[7],
                            ];
                            results.extend(kk_kdf_batch_8(KEY, SALT, batch, OUTPUT_LEN));
                        } else {
                            for info in chunk {
                                results.push(kk_kdf(KEY, SALT, info, OUTPUT_LEN));
                            }
                        }
                    }
                    black_box(results);
                });
            });
        }
    }
    group.finish();
}

fn bench_gpu_permute_batch(c: &mut Criterion) {
    use kk_crypto::kk_mix::{KkSponge, KkState, ROUNDS};

    let gpu = GpuAccelerator::new().expect("GPU required for this benchmark");
    let sponge = KkSponge::new();
    let iv = sponge.state();
    let rotations = sponge.rotations();

    let mut group = c.benchmark_group("gpu_permute_batch");

    for &n in &[64, 256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes((n * 200) as u64)); // 200 bytes per state

        group.bench_with_input(BenchmarkId::new("gpu", n), &n, |b, &n| {
            let mut states: Vec<KkState> = (0..n).map(|_| iv).collect();
            b.iter(|| {
                gpu.permute_batch(&mut states, &rotations, ROUNDS);
                black_box(&states);
            });
        });
    }
    group.finish();
}

criterion_group!(gpu_benches, bench_gpu_kdf_batch, bench_gpu_permute_batch);
criterion_main!(gpu_benches);
