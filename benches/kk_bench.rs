// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;
use kk_crypto::{decode, encode, encode_pooled, EntropyPool, KkPacket};
use kk_crypto::{encode_aead, decode_aead, encode_aead_batch, decode_aead_batch, KkAeadPacket};

const SECRET: &[u8] = b"bench-shared-secret-2026";

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");

    for size in [1, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 10485760] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encode(black_box(SECRET), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    for size in [1, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 10485760] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let packet = encode(SECRET, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &packet, |b, pkt| {
            b.iter(|| decode(black_box(SECRET), black_box(pkt)).unwrap());
        });
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for size in [64, 1024, 16384, 262144, 1048576] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let pkt = encode(black_box(SECRET), black_box(pt)).unwrap();
                decode(black_box(SECRET), black_box(&pkt)).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_packet_serialization(c: &mut Criterion) {
    let plaintext = b"packet serialization benchmark data here";
    let packet = encode(SECRET, plaintext).unwrap();
    let wire = packet.to_bytes();

    let mut group = c.benchmark_group("packet_serde");
    group.bench_function("to_bytes", |b| {
        b.iter(|| black_box(&packet).to_bytes());
    });
    group.bench_function("from_bytes", |b| {
        b.iter(|| KkPacket::from_bytes(black_box(&wire)).unwrap());
    });
    group.finish();
}

fn bench_entropy(c: &mut Criterion) {
    c.bench_function("entropy_gather", |b| {
        b.iter(|| kk_crypto::EntropySnapshot::from_bytes(&kk_crypto::encode(SECRET, b"x").unwrap().entropy_snapshot.to_bytes()).unwrap());
    });
}

fn bench_encode_huge(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_huge");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for size in [33_554_432u64, 67_108_864, 134_217_728, 268_435_456] {
        let plaintext: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encode(black_box(SECRET), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

fn bench_decode_huge(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_huge");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for size in [33_554_432u64, 67_108_864, 134_217_728, 268_435_456] {
        let plaintext: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
        let packet = encode(SECRET, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &packet, |b, pkt| {
            b.iter(|| decode(black_box(SECRET), black_box(pkt)).unwrap());
        });
    }
    group.finish();
}

fn bench_roundtrip_huge(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip_huge");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    for size in [10_485_760u64, 33_554_432, 67_108_864, 134_217_728] {
        let plaintext: Vec<u8> = (0..size as usize).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let pkt = encode(black_box(SECRET), black_box(pt)).unwrap();
                decode(black_box(SECRET), black_box(&pkt)).unwrap()
            });
        });
    }
    group.finish();
}

fn bench_encode_pooled(c: &mut Criterion) {
    let pool = EntropyPool::new(64).unwrap();
    let mut group = c.benchmark_group("encode_pooled");

    for size in [1, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 10485760] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encode_pooled(black_box(SECRET), black_box(pt), &pool).unwrap());
        });
    }
    group.finish();
}

fn bench_entropy_pool_draw(c: &mut Criterion) {
    let pool = EntropyPool::new(128).unwrap();
    c.bench_function("entropy_pool_draw", |b| {
        b.iter(|| pool.draw().unwrap());
    });
}

/// Compare scalar (8× sequential kk_kdf) vs batch (kk_kdf_batch_8, AVX-512 when available).
fn bench_avx512_vs_scalar(c: &mut Criterion) {
    use kk_crypto::kk_mix::{kk_kdf, kk_kdf_batch_8};

    let key = b"benchmark-key-for-kdf-comparison";
    let salt = b"benchmark-salt";
    let infos: [&[u8]; 8] = [
        b"info-0", b"info-1", b"info-2", b"info-3",
        b"info-4", b"info-5", b"info-6", b"info-7",
    ];

    for output_len in [32, 64, 256] {
        let mut group = c.benchmark_group(format!("kdf_8x_{output_len}B"));

        group.bench_function("scalar_sequential", |b| {
            b.iter(|| {
                for i in 0..8 {
                    black_box(kk_kdf(
                        black_box(key),
                        black_box(salt),
                        black_box(infos[i]),
                        output_len,
                    ));
                }
            });
        });

        group.bench_function("batch_kdf_batch_8", |b| {
            b.iter(|| {
                black_box(kk_kdf_batch_8(
                    black_box(key),
                    black_box(salt),
                    black_box(infos),
                    output_len,
                ));
            });
        });

        group.finish();
    }
}

/// Batched AEAD: N independent messages encrypted/decrypted in parallel.
fn bench_batch_aead_encode(c: &mut Criterion) {
    let pool = EntropyPool::new(256).unwrap();
    let secret = b"batch-aead-bench-secret-2026";

    // (message_count, message_size_bytes)
    let configs: &[(usize, usize, &str)] = &[
        (1000, 1024, "1000x1KB"),
        (1000, 4096, "1000x4KB"),
        (1000, 16384, "1000x16KB"),
        (1000, 65536, "1000x64KB"),
        (10000, 4096, "10000x4KB"),
    ];

    for &(count, size, label) in configs {
        let aad = b"bench-aad";
        let plaintext = vec![0xABu8; size];
        let messages: Vec<(&[u8], &[u8])> = (0..count)
            .map(|_| (plaintext.as_slice(), aad.as_slice()))
            .collect();
        let total_bytes = (count * size) as u64;

        let mut group = c.benchmark_group(format!("batch_aead_{label}"));
        group.throughput(Throughput::Bytes(total_bytes));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(20));

        group.bench_function("pooled", |b| {
            b.iter(|| {
                black_box(encode_aead_batch(
                    black_box(secret),
                    black_box(&messages),
                    Some(&pool),
                ).unwrap());
            });
        });

        group.bench_function("no_pool", |b| {
            b.iter(|| {
                black_box(encode_aead_batch(
                    black_box(secret),
                    black_box(&messages),
                    None,
                ).unwrap());
            });
        });

        group.finish();
    }
}

fn bench_batch_aead_roundtrip(c: &mut Criterion) {
    let pool = EntropyPool::new(256).unwrap();
    let secret = b"batch-aead-bench-secret-2026";

    let configs: &[(usize, usize, &str)] = &[
        (1000, 1024, "1000x1KB"),
        (1000, 4096, "1000x4KB"),
        (1000, 65536, "1000x64KB"),
    ];

    for &(count, size, label) in configs {
        let aad = b"bench-aad";
        let plaintext = vec![0xABu8; size];
        let messages: Vec<(&[u8], &[u8])> = (0..count)
            .map(|_| (plaintext.as_slice(), aad.as_slice()))
            .collect();
        let total_bytes = (count * size) as u64;

        let mut group = c.benchmark_group(format!("batch_roundtrip_{label}"));
        group.throughput(Throughput::Bytes(total_bytes));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(20));

        group.bench_function("pooled", |b| {
            b.iter(|| {
                let packets = encode_aead_batch(secret, &messages, Some(&pool)).unwrap();
                black_box(decode_aead_batch(secret, &packets).unwrap());
            });
        });

        group.finish();
    }
}

criterion_group!(
    benches,
    bench_encode,
    bench_decode,
    bench_roundtrip,
    bench_packet_serialization,
    bench_entropy,
    bench_encode_pooled,
    bench_entropy_pool_draw,
    bench_avx512_vs_scalar,
);

criterion_group!(
    name = benches_huge;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(30));
    targets = bench_encode_huge, bench_decode_huge, bench_roundtrip_huge
);

criterion_group!(
    name = benches_batch;
    config = Criterion::default();
    targets = bench_batch_aead_encode, bench_batch_aead_roundtrip
);

criterion_main!(benches, benches_huge, benches_batch);
