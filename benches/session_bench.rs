// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kk_crypto::session::{decode_session, encode_session, RopePacket, RopeRatchet};

const SECRET: &[u8] = b"bench-shared-secret-2026";
const CONTEXT: &[u8] = b"bench-direction-a-to-b";

// ─────────────────────────────────────────────────────────────────
//  Ratchet initialization
// ─────────────────────────────────────────────────────────────────

fn bench_ratchet_init(c: &mut Criterion) {
    c.bench_function("rope_ratchet_init", |b| {
        b.iter(|| RopeRatchet::new(black_box(SECRET), black_box(CONTEXT)).unwrap());
    });
}

// ─────────────────────────────────────────────────────────────────
//  Ratchet advance (sender-side step only, no encode)
// ─────────────────────────────────────────────────────────────────

fn bench_ratchet_advance(c: &mut Criterion) {
    let mut ratchet = RopeRatchet::new(SECRET, CONTEXT).unwrap();
    c.bench_function("rope_ratchet_advance", |b| {
        b.iter(|| {
            let (key, _step) = ratchet.advance().unwrap();
            black_box(key);
        });
    });
}

// ─────────────────────────────────────────────────────────────────
//  Ratchet advance + receive (simulate both sides without codec)
// ─────────────────────────────────────────────────────────────────

fn bench_ratchet_advance_receive(c: &mut Criterion) {
    let mut sender = RopeRatchet::new(SECRET, CONTEXT).unwrap();
    let mut receiver = RopeRatchet::new(SECRET, CONTEXT).unwrap();
    c.bench_function("rope_advance_then_receive", |b| {
        b.iter(|| {
            let (send_key, step) = sender.advance().unwrap();
            let recv_key = receiver.receive(&step).unwrap();
            black_box((send_key, recv_key));
        });
    });
}

// ─────────────────────────────────────────────────────────────────
//  Full session encode at various payload sizes
// ─────────────────────────────────────────────────────────────────

fn bench_session_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_encode");

    for size in [1, 64, 256, 1024, 4096, 16384, 65536] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let mut ratchet = RopeRatchet::new(SECRET, CONTEXT).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| encode_session(black_box(&mut ratchet), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Full session decode at various payload sizes
// ─────────────────────────────────────────────────────────────────

fn bench_session_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_decode");

    for size in [1, 64, 256, 1024, 4096, 16384, 65536] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let mut sender = RopeRatchet::new(SECRET, CONTEXT).unwrap();
        let mut receiver = RopeRatchet::new(SECRET, CONTEXT).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                // Encode and decode stay in lock-step (strict counter)
                let pkt = encode_session(&mut sender, pt).unwrap();
                decode_session(black_box(&mut receiver), black_box(&pkt)).unwrap()
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Full session roundtrip (encode + decode)
// ─────────────────────────────────────────────────────────────────

fn bench_session_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_roundtrip");

    for size in [64, 1024, 16384, 65536] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let mut sender = RopeRatchet::new(SECRET, CONTEXT).unwrap();
        let mut receiver = RopeRatchet::new(SECRET, CONTEXT).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let pkt = encode_session(black_box(&mut sender), black_box(pt)).unwrap();
                let out = decode_session(black_box(&mut receiver), black_box(&pkt)).unwrap();
                black_box(out);
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  RopePacket wire serialization
// ─────────────────────────────────────────────────────────────────

fn bench_rope_packet_serde(c: &mut Criterion) {
    let mut ratchet = RopeRatchet::new(SECRET, CONTEXT).unwrap();
    let packet = encode_session(&mut ratchet, b"packet serde bench payload").unwrap();
    let wire = packet.to_bytes();

    let mut group = c.benchmark_group("rope_packet_serde");
    group.bench_function("to_bytes", |b| {
        b.iter(|| black_box(&packet).to_bytes());
    });
    group.bench_function("from_bytes", |b| {
        b.iter(|| RopePacket::from_bytes(black_box(&wire)).unwrap());
    });
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Forward secrecy overhead: session encode vs raw encode
// ─────────────────────────────────────────────────────────────────

fn bench_forward_secrecy_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("fs_overhead");

    for size in [64, 1024, 16384] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

        // Raw encode (no forward secrecy)
        group.bench_with_input(
            BenchmarkId::new("raw_encode", size),
            &plaintext,
            |b, pt| {
                b.iter(|| kk_crypto::encode(black_box(SECRET), black_box(pt)).unwrap());
            },
        );

        // Session encode (with forward secrecy)
        let mut ratchet = RopeRatchet::new(SECRET, CONTEXT).unwrap();
        group.bench_with_input(
            BenchmarkId::new("session_encode", size),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    encode_session(black_box(&mut ratchet), black_box(pt)).unwrap()
                });
            },
        );
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Sustained ratchet throughput: N advances in a burst
// ─────────────────────────────────────────────────────────────────

fn bench_ratchet_burst(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_burst");

    for n in [10, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &count| {
            b.iter(|| {
                let mut r = RopeRatchet::new(SECRET, CONTEXT).unwrap();
                for _ in 0..count {
                    let (key, _step) = r.advance().unwrap();
                    black_box(key);
                }
            });
        });
    }
    group.finish();
}

// ─────────────────────────────────────────────────────────────────
//  Wire size: measure packet expansion at various plaintext sizes
// ─────────────────────────────────────────────────────────────────

fn bench_wire_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_expansion");

    for size in [1, 64, 256, 1024, 4096] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let mut ratchet = RopeRatchet::new(SECRET, CONTEXT).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| {
                let pkt = encode_session(black_box(&mut ratchet), black_box(pt)).unwrap();
                let wire = pkt.to_bytes();
                black_box(wire.len());
            });
        });
    }
    group.finish();
}

criterion_group!(
    session_benches,
    bench_ratchet_init,
    bench_ratchet_advance,
    bench_ratchet_advance_receive,
    bench_session_encode,
    bench_session_decode,
    bench_session_roundtrip,
    bench_rope_packet_serde,
    bench_forward_secrecy_overhead,
    bench_ratchet_burst,
    bench_wire_expansion,
);
criterion_main!(session_benches);
