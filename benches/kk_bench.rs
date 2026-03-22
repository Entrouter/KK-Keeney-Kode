// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kk_crypto::{decode, encode, KkPacket};

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

criterion_group!(
    benches,
    bench_encode,
    bench_decode,
    bench_roundtrip,
    bench_packet_serialization,
    bench_entropy,
    bench_avx512_vs_scalar,
);
criterion_main!(benches);
