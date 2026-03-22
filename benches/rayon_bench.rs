// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Rayon multi-core scaling benchmark.
//!
//! Compares single-threaded (1 core) vs full multi-threaded (all cores)
//! to measure actual parallelism gain on this hardware.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

use kk_crypto::{
    decode, encode, encode_aead_batch, decode_aead_batch,
    EntropyPool, encode_parallel,
};

const SECRET: &[u8] = b"rayon-scaling-bench-secret-2026";

// ---------------------------------------------------------------------------
// Single large‐payload encode: 1 thread vs ALL threads
// ---------------------------------------------------------------------------
fn bench_encode_scaling(c: &mut Criterion) {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(16);

    let pool1 = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool_all = rayon::ThreadPoolBuilder::new().num_threads(num_cpus).build().unwrap();

    let mut group = c.benchmark_group("encode_scaling");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for size in [1_048_576u64, 10_485_760, 33_554_432, 67_108_864, 134_217_728] {
        let plaintext: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(
            BenchmarkId::new("1_thread", size),
            &plaintext,
            |b, pt| {
                b.iter(|| pool1.install(|| encode(black_box(SECRET), black_box(pt)).unwrap()));
            },
        );

        group.bench_with_input(
            BenchmarkId::new(format!("{num_cpus}_threads"), size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    pool_all.install(|| encode(black_box(SECRET), black_box(pt)).unwrap())
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Single large‐payload decode: 1 thread vs ALL threads
// ---------------------------------------------------------------------------
fn bench_decode_scaling(c: &mut Criterion) {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(16);

    let pool1 = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool_all = rayon::ThreadPoolBuilder::new().num_threads(num_cpus).build().unwrap();

    let mut group = c.benchmark_group("decode_scaling");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(10);

    for size in [1_048_576u64, 10_485_760, 33_554_432, 67_108_864, 134_217_728] {
        let plaintext: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
        let packet = encode(SECRET, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(
            BenchmarkId::new("1_thread", size),
            &packet,
            |b, pkt| {
                b.iter(|| pool1.install(|| decode(black_box(SECRET), black_box(pkt)).unwrap()));
            },
        );

        group.bench_with_input(
            BenchmarkId::new(format!("{num_cpus}_threads"), size),
            &packet,
            |b, pkt| {
                b.iter(|| {
                    pool_all.install(|| decode(black_box(SECRET), black_box(pkt)).unwrap())
                });
            },
        );
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Batch AEAD encode: 1 thread vs ALL threads
// ---------------------------------------------------------------------------
fn bench_batch_aead_scaling(c: &mut Criterion) {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(16);
    let epool = EntropyPool::new(256).unwrap();

    let pool1 = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool_all = rayon::ThreadPoolBuilder::new().num_threads(num_cpus).build().unwrap();

    let configs: &[(usize, usize, &str)] = &[
        (1000, 1024, "1Kx1KB"),
        (1000, 4096, "1Kx4KB"),
        (4000, 4096, "4Kx4KB"),
        (1000, 65536, "1Kx64KB"),
        (10000, 4096, "10Kx4KB"),
    ];

    for &(count, size, label) in configs {
        let aad = b"bench-aad";
        let plaintext = vec![0xABu8; size];
        let messages: Vec<(&[u8], &[u8])> = (0..count)
            .map(|_| (plaintext.as_slice(), aad.as_slice()))
            .collect();
        let total_bytes = (count * size) as u64;

        let mut group = c.benchmark_group(format!("batch_aead_scaling_{label}"));
        group.throughput(Throughput::Bytes(total_bytes));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(20));

        group.bench_function("1_thread", |b| {
            b.iter(|| {
                pool1.install(|| {
                    encode_aead_batch(black_box(SECRET), black_box(&messages), Some(&epool)).unwrap()
                })
            });
        });

        group.bench_function(format!("{num_cpus}_threads"), |b| {
            b.iter(|| {
                pool_all.install(|| {
                    encode_aead_batch(black_box(SECRET), black_box(&messages), Some(&epool)).unwrap()
                })
            });
        });

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// Batch AEAD decode: 1 thread vs ALL threads
// ---------------------------------------------------------------------------
fn bench_batch_aead_decode_scaling(c: &mut Criterion) {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(16);
    let epool = EntropyPool::new(256).unwrap();

    let pool1 = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool_all = rayon::ThreadPoolBuilder::new().num_threads(num_cpus).build().unwrap();

    let configs: &[(usize, usize, &str)] = &[
        (1000, 4096, "1Kx4KB"),
        (1000, 65536, "1Kx64KB"),
        (10000, 4096, "10Kx4KB"),
    ];

    for &(count, size, label) in configs {
        let aad = b"bench-aad";
        let plaintext = vec![0xABu8; size];
        let messages: Vec<(&[u8], &[u8])> = (0..count)
            .map(|_| (plaintext.as_slice(), aad.as_slice()))
            .collect();
        let packets = encode_aead_batch(SECRET, &messages, Some(&epool)).unwrap();
        let total_bytes = (count * size) as u64;

        let mut group = c.benchmark_group(format!("batch_decode_scaling_{label}"));
        group.throughput(Throughput::Bytes(total_bytes));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(20));

        group.bench_function("1_thread", |b| {
            b.iter(|| {
                pool1.install(|| {
                    decode_aead_batch(black_box(SECRET), black_box(&packets)).unwrap()
                })
            });
        });

        group.bench_function(format!("{num_cpus}_threads"), |b| {
            b.iter(|| {
                pool_all.install(|| {
                    decode_aead_batch(black_box(SECRET), black_box(&packets)).unwrap()
                })
            });
        });

        group.finish();
    }
}

// ---------------------------------------------------------------------------
// encode_parallel (chunked Merkle): 1 thread vs ALL threads
// ---------------------------------------------------------------------------
fn bench_parallel_encode_scaling(c: &mut Criterion) {
    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(16);
    let epool = EntropyPool::new(256).unwrap();

    let pool1 = rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap();
    let pool_all = rayon::ThreadPoolBuilder::new().num_threads(num_cpus).build().unwrap();

    let mut group = c.benchmark_group("parallel_encode_scaling");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    for size in [10_485_760u64, 33_554_432, 67_108_864, 134_217_728] {
        let plaintext: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
        let aad = b"scaling-aad";
        let chunk = 1_048_576; // 1 MiB chunks
        group.throughput(Throughput::Bytes(size));

        group.bench_with_input(
            BenchmarkId::new("1_thread", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    pool1.install(|| {
                        encode_parallel(
                            black_box(SECRET),
                            black_box(pt),
                            black_box(aad),
                            chunk,
                            Some(&epool),
                        )
                        .unwrap()
                    })
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new(format!("{num_cpus}_threads"), size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    pool_all.install(|| {
                        encode_parallel(
                            black_box(SECRET),
                            black_box(pt),
                            black_box(aad),
                            chunk,
                            Some(&epool),
                        )
                        .unwrap()
                    })
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    name = scaling;
    config = Criterion::default();
    targets =
        bench_encode_scaling,
        bench_decode_scaling,
        bench_batch_aead_scaling,
        bench_batch_aead_decode_scaling,
        bench_parallel_encode_scaling
);

criterion_main!(scaling);
