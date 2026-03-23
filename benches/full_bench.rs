// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Comprehensive benchmark suite for KK-Crypto.
//!
//! Covers every public API surface NOT already benchmarked in kk_bench or
//! session_bench: primitives (hash, KDF, MAC, permutation), AEAD codec,
//! split codec, bound codec, session AEAD, EKA handshake, and temporal
//! commitment.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kk_crypto::{
    decode_aead,
    decode_bound,
    decode_parallel,
    decode_session_aead,
    decode_split,
    // Codec modes
    encode_aead,
    encode_bound,
    // Parallel encode
    encode_parallel,
    // Session AEAD
    encode_session_aead,
    encode_split,
    generate_challenge,
    // Primitives
    kk_mix::{
        kk_entropy_mix, kk_hash, kk_kdf, kk_kdf_batch_8, kk_mac, kk_mac_verify, kk_permute,
        kk_permute_with_schedule, rotations_from_entropy, KkState,
    },
    // EKA
    EkaInitiator,
    EkaResponder,
    // Entropy pool
    EntropyPool,
    RopeRatchet,
    GENESIS_MAC,
    PARALLEL_CHUNK_SIZE,
};
use std::time::Duration;

const SECRET: &[u8] = b"bench-shared-secret-2026";

// ─────────────────────────────────────────────────────────────────
//  Primitives
// ─────────────────────────────────────────────────────────────────

fn bench_kk_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_hash");
    for size in [32, 64, 256, 1024, 4096, 65536] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| kk_hash(black_box(d)));
        });
    }
    group.finish();
}

fn bench_kk_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_kdf");
    let key = b"benchmark-kdf-key-material";
    let salt = b"benchmark-kdf-salt";
    for out_len in [32, 64, 128, 256, 512] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(out_len), &out_len, |b, &len| {
            b.iter(|| kk_kdf(black_box(key), black_box(salt), black_box(b"info"), len));
        });
    }
    group.finish();
}

fn bench_kk_kdf_batch_8(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_kdf_batch_8");
    let key = b"benchmark-kdf-key-material";
    let salt = b"benchmark-kdf-salt";
    let infos: [&[u8]; 8] = [
        b"info-0", b"info-1", b"info-2", b"info-3", b"info-4", b"info-5", b"info-6", b"info-7",
    ];
    for out_len in [32, 64, 128] {
        group.throughput(Throughput::Bytes((out_len * 8) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(out_len), &out_len, |b, &len| {
            b.iter(|| kk_kdf_batch_8(black_box(key), black_box(salt), infos, len));
        });
    }
    group.finish();
}

fn bench_kk_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_mac");
    let key = b"benchmark-mac-key-32-bytes-long!";
    for size in [32, 64, 256, 1024, 4096, 65536] {
        let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &message, |b, m| {
            b.iter(|| kk_mac(black_box(key), black_box(m)));
        });
    }
    group.finish();
}

fn bench_kk_mac_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_mac_verify");
    let key = b"benchmark-mac-key-32-bytes-long!";
    for size in [32, 256, 4096] {
        let message: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let tag = kk_mac(key, &message);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(message, tag),
            |b, (m, t)| {
                b.iter(|| kk_mac_verify(black_box(key), black_box(m), black_box(t)));
            },
        );
    }
    group.finish();
}

fn bench_kk_permute(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_permute");
    let mut state: KkState = [0x0123456789abcdef_u64; 25];
    group.bench_function("default_rotations", |b| {
        b.iter(|| kk_permute(black_box(&mut state)));
    });

    let entropy = [0xABu8; 32];
    let rotations = rotations_from_entropy(&entropy);
    group.bench_function("custom_rotations", |b| {
        b.iter(|| kk_permute_with_schedule(black_box(&mut state), black_box(&rotations)));
    });
    group.finish();
}

fn bench_rotations_from_entropy(c: &mut Criterion) {
    let entropy = [0x42u8; 32];
    c.bench_function("rotations_from_entropy", |b| {
        b.iter(|| rotations_from_entropy(black_box(&entropy)));
    });
}

fn bench_kk_entropy_mix(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_entropy_mix");
    let src_a = [0x11u8; 32];
    let src_b = [0x22u8; 48];
    let src_c = [0x33u8; 64];
    let sources: Vec<&[u8]> = vec![&src_a, &src_b, &src_c];
    for out_len in [32, 64, 128] {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(out_len), &out_len, |b, &len| {
            b.iter(|| kk_entropy_mix(black_box(&sources), len));
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  AEAD Codec
// ─────────────────────────────────────────────────────────────────

fn bench_encode_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_aead");
    let aad = b"benchmark-associated-data";
    for size in [64, 1024, 16384, 65536] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encode_aead(black_box(SECRET), black_box(pt), black_box(aad)).unwrap());
        });
    }
    group.finish();
}

fn bench_decode_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_aead");
    let aad = b"benchmark-associated-data";
    for size in [64, 1024, 16384, 65536] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let packet = encode_aead(SECRET, &plaintext, aad).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &packet, |b, pkt| {
            b.iter(|| decode_aead(black_box(SECRET), black_box(pkt)).unwrap());
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Split Codec
// ─────────────────────────────────────────────────────────────────

fn bench_encode_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_split");
    for size in [64, 1024, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encode_split(black_box(SECRET), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

fn bench_decode_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_split");
    for size in [64, 1024, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let (sealed, epsilon) = encode_split(SECRET, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &(sealed, epsilon),
            |b, (s, e)| {
                b.iter(|| decode_split(black_box(SECRET), black_box(s), black_box(e)).unwrap());
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Bound Codec (challenge-response temporal proof)
// ─────────────────────────────────────────────────────────────────

fn bench_encode_bound(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_bound");
    let nonce = generate_challenge().unwrap();
    for size in [64, 1024, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                encode_bound(
                    black_box(SECRET),
                    black_box(pt),
                    black_box(&nonce),
                    black_box(&GENESIS_MAC),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_decode_bound(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_bound");
    let nonce = generate_challenge().unwrap();
    let max_drift = Duration::from_secs(3600); // large window for benchmarking
    for size in [64, 1024, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let packet = encode_bound(SECRET, &plaintext, &nonce, &GENESIS_MAC).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &packet, |b, pkt| {
            b.iter(|| {
                decode_bound(
                    black_box(SECRET),
                    black_box(pkt),
                    black_box(&nonce),
                    black_box(max_drift),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Session AEAD (forward-secret + associated data)
// ─────────────────────────────────────────────────────────────────

fn bench_session_aead_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_aead_roundtrip");
    let aad = b"session-metadata";
    for size in [64, 1024, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    let mut sender = RopeRatchet::new(SECRET, b"bench").unwrap();
                    let mut receiver = RopeRatchet::new(SECRET, b"bench").unwrap();
                    let start = std::time::Instant::now();
                    let pkt = encode_session_aead(&mut sender, pt, aad).unwrap();
                    let _ = decode_session_aead(&mut receiver, &pkt).unwrap();
                    total += start.elapsed();
                }
                total
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  EKA Handshake (3-message key agreement)
// ─────────────────────────────────────────────────────────────────

fn bench_eka_handshake(c: &mut Criterion) {
    c.bench_function("eka_full_handshake", |b| {
        b.iter(|| {
            let psk = black_box(b"eka-bench-psk-2026");
            let (alice, msg1) = EkaInitiator::new(psk).unwrap();
            let (bob, msg2) = EkaResponder::new(psk, &msg1).unwrap();
            let (msg3, alice_key) = alice.process_msg2(&msg2).unwrap();
            let bob_key = bob.process_msg3(&msg3).unwrap();
            assert_eq!(alice_key, bob_key);
            black_box(alice_key)
        });
    });
}

// ─────────────────────────────────────────────────────────────────
//  Temporal Commitment (commit + verify cycle)
// ─────────────────────────────────────────────────────────────────

fn bench_temporal_commit_verify(c: &mut Criterion) {
    use kk_crypto::temporal;

    let mut group = c.benchmark_group("temporal_commitment");
    for size in [64, 1024] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        // Pre-encode to get a snapshot + ciphertext pair
        let packet = kk_crypto::encode(SECRET, &plaintext).unwrap();

        group.bench_with_input(BenchmarkId::new("commit", size), &packet, |b, pkt| {
            b.iter(|| {
                temporal::commit(
                    black_box(SECRET),
                    black_box(&pkt.entropy_snapshot),
                    black_box(&pkt.ciphertext),
                )
                .unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("verify", size), &packet, |b, pkt| {
            let commitment =
                temporal::commit(SECRET, &pkt.entropy_snapshot, &pkt.ciphertext).unwrap();
            b.iter(|| {
                temporal::verify(
                    black_box(SECRET),
                    black_box(&pkt.entropy_snapshot),
                    black_box(&pkt.ciphertext),
                    black_box(&commitment),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Entropy Snapshot Gather
// ─────────────────────────────────────────────────────────────────

fn bench_entropy_snapshot(c: &mut Criterion) {
    c.bench_function("entropy_gather", |b| {
        b.iter(|| {
            let snap = kk_crypto::entropy::gather().unwrap();
            black_box(snap)
        });
    });
}

// ─────────────────────────────────────────────────────────────────
//  Wire Format Serialization
// ─────────────────────────────────────────────────────────────────

fn bench_aead_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_packet_serde");
    let aad = b"bench-aad";
    for size in [64, 4096] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let packet = encode_aead(SECRET, &plaintext, aad).unwrap();
        let bytes = packet.to_bytes();

        group.bench_with_input(BenchmarkId::new("to_bytes", size), &packet, |b, pkt| {
            b.iter(|| black_box(pkt.to_bytes()));
        });
        group.bench_with_input(BenchmarkId::new("from_bytes", size), &bytes, |b, data| {
            b.iter(|| kk_crypto::KkAeadPacket::from_bytes(black_box(data)).unwrap());
        });
    }
    group.finish();
}

fn bench_bound_serde(c: &mut Criterion) {
    let mut group = c.benchmark_group("bound_packet_serde");
    let nonce = generate_challenge().unwrap();
    for size in [64, 4096] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let packet = encode_bound(SECRET, &plaintext, &nonce, &GENESIS_MAC).unwrap();
        let bytes = packet.to_bytes();

        group.bench_with_input(BenchmarkId::new("to_bytes", size), &packet, |b, pkt| {
            b.iter(|| black_box(pkt.to_bytes()));
        });
        group.bench_with_input(BenchmarkId::new("from_bytes", size), &bytes, |b, data| {
            b.iter(|| kk_crypto::KkBoundPacket::from_bytes(black_box(data)).unwrap());
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  KK-RNG (deterministic PRNG from KK sponge)
// ─────────────────────────────────────────────────────────────────

fn bench_rng_next_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_rng_next_bytes");
    for size in [32, 64, 256, 1024, 4096, 65536] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &len| {
            let mut rng = kk_crypto::KkRng::new(b"bench-seed-for-rng-2026");
            b.iter(|| black_box(rng.next_bytes(len)));
        });
    }
    group.finish();
}

fn bench_rng_next_u64(c: &mut Criterion) {
    let mut rng = kk_crypto::KkRng::new(b"bench-seed-for-rng-2026");
    c.bench_function("kk_rng_next_u64", |b| {
        b.iter(|| black_box(rng.next_u64()));
    });
}

fn bench_rng_reseed(c: &mut Criterion) {
    let mut rng = kk_crypto::KkRng::new(b"bench-seed-for-rng-2026");
    c.bench_function("kk_rng_reseed", |b| {
        b.iter(|| rng.reseed(black_box(b"fresh-entropy-material")));
    });
}

// ─────────────────────────────────────────────────────────────────
//  KkRngPool - Parallel RNG throughput
// ─────────────────────────────────────────────────────────────────

fn bench_rng_pool_next_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_rng_pool_next_bytes");
    let num_gen = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    for size in [256, 1024, 4096, 65536] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("{}gen", num_gen), size),
            &size,
            |b, &len| {
                let pool = kk_crypto::KkRngPool::new(b"bench-pool-seed-2026", num_gen);
                b.iter(|| black_box(pool.next_bytes(len)));
            },
        );
    }
    group.finish();
}

fn bench_rng_pool_fill_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("kk_rng_pool_fill_parallel");
    let num_gen = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    for total in [65_536usize, 1_048_576, 10_485_760, 104_857_600] {
        group.throughput(Throughput::Bytes(total as u64));
        let label = match total {
            65_536 => "64KB",
            1_048_576 => "1MB",
            10_485_760 => "10MB",
            _ => "100MB",
        };
        group.bench_function(BenchmarkId::new(format!("{}gen", num_gen), label), |b| {
            let pool = kk_crypto::KkRngPool::new(b"bench-pool-seed-2026", num_gen);
            let mut buf = vec![0u8; total];
            b.iter(|| {
                pool.fill_bytes_parallel(black_box(&mut buf));
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Parallel Encode / Decode
// ─────────────────────────────────────────────────────────────────

fn bench_encode_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_parallel");
    let pool = EntropyPool::new(256).unwrap();
    for &size in &[1 << 20, 10 << 20, 100 << 20] {
        let label = match size {
            1_048_576 => "1MB",
            10_485_760 => "10MB",
            _ => "100MB",
        };
        group.throughput(Throughput::Bytes(size as u64));
        group.sample_size(10);
        group.bench_with_input(BenchmarkId::from_parameter(label), &size, |b, &sz| {
            let payload = vec![0xABu8; sz];
            let aad = b"bench-aad";
            b.iter(|| {
                encode_parallel(
                    black_box(SECRET),
                    black_box(&payload),
                    black_box(aad),
                    PARALLEL_CHUNK_SIZE,
                    Some(&pool),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_decode_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_parallel");
    let pool = EntropyPool::new(256).unwrap();
    for &size in &[1 << 20, 10 << 20, 100 << 20] {
        let label = match size {
            1_048_576 => "1MB",
            10_485_760 => "10MB",
            _ => "100MB",
        };
        group.throughput(Throughput::Bytes(size as u64));
        group.sample_size(10);
        let payload = vec![0xABu8; size];
        let packet = encode_parallel(
            SECRET,
            &payload,
            b"bench-aad",
            PARALLEL_CHUNK_SIZE,
            Some(&pool),
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(label), &packet, |b, pkt| {
            b.iter(|| decode_parallel(black_box(SECRET), black_box(pkt)).unwrap());
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Registration
// ─────────────────────────────────────────────────────────────────

criterion_group!(
    primitives,
    bench_kk_hash,
    bench_kk_kdf,
    bench_kk_kdf_batch_8,
    bench_kk_mac,
    bench_kk_mac_verify,
    bench_kk_permute,
    bench_rotations_from_entropy,
    bench_kk_entropy_mix,
);

criterion_group!(
    codec_aead,
    bench_encode_aead,
    bench_decode_aead,
    bench_aead_serde,
);

criterion_group!(codec_split, bench_encode_split, bench_decode_split,);

criterion_group!(
    codec_bound,
    bench_encode_bound,
    bench_decode_bound,
    bench_bound_serde,
);

criterion_group!(
    session_and_eka,
    bench_session_aead_roundtrip,
    bench_eka_handshake,
);

criterion_group!(
    temporal_and_entropy,
    bench_temporal_commit_verify,
    bench_entropy_snapshot,
);

criterion_group!(
    rng,
    bench_rng_next_bytes,
    bench_rng_next_u64,
    bench_rng_reseed,
);

criterion_group!(
    rng_parallel,
    bench_rng_pool_next_bytes,
    bench_rng_pool_fill_parallel,
);

criterion_group!(
    parallel_encode,
    bench_encode_parallel,
    bench_decode_parallel,
);

criterion_main!(
    primitives,
    codec_aead,
    codec_split,
    codec_bound,
    session_and_eka,
    temporal_and_entropy,
    rng,
    rng_parallel,
    parallel_encode,
);
