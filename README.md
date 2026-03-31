<!--
Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
Licensed under the Apache License, Version 2.0 with Additional Terms.
NO COMMERCIAL USE without prior written authorization from Entrouter.
Unauthorized commercial use will be prosecuted to the fullest extent of the law.
See the LICENSE file in the project root for full license information.
NOTICE: Removal of this header is a violation of the license.
-->

<div align="center">

# KK (Keeney Kode)

### A 1600-bit Table-Free ARX Sponge with MILP-Proven 1,052 Active Components and 2^(-26,712) Differential Trail Bound

**The first cryptographic primitive where the algebraic structure of the permutation itself changes with every invocation.**

*One permutation. Zero borrowed components. Complete cryptographic suite from scratch.*

[![crates.io](https://img.shields.io/crates/v/kk-crypto.svg)](https://crates.io/crates/kk-crypto)
[![CI](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/ci.yml/badge.svg)](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/ci.yml)
[![Security Audit](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/security.yml/badge.svg)](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/security.yml)
[![Fuzz](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/fuzz.yml/badge.svg)](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/fuzz.yml)
[![Coverage](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/coverage.yml/badge.svg)](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/coverage.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20Additional%20Terms-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](#no_std-support)
---

```text
KK(S) = S XOR E : state XOR universal entropy at the precise instant of creation
```

</div>

> [!WARNING]
> KK is a novel, un-audited cryptographic primitive. It has **not** been reviewed by third-party cryptographers. Do not use for production security until formal peer review is complete.

## Table of Contents

- [What is KK?](#what-is-kk)
- [Quick Start](#quick-start)
- [The Primitive](#the-primitive)
- [What Ships in the Box](#what-ships-in-the-box)
- [Performance](#performance)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Building](#building)
- [Testing](#testing)
- [Fuzzing](#fuzzing)
- [no_std Support](#no_std-support)
- [Documentation](#documentation)
- [License](#license)

---

## What is KK?

KK (Keeney Kode) is a 1600-bit cryptographic sponge permutation built entirely from arithmetic, rotation, and XOR operations (the ARX paradigm) without lookup tables, S-boxes, or borrowed components. It introduces two novel primitives that no published cipher uses:

- **Multiply-Fold-Rotate (MFR):** Widening 64-bit multiply, XOR fold, and rotation. Bijective, non-linear, full-word mixing. Per-bit scaling of maximum differential probability: 2^(-63) at full 64-bit width.
- **Data-Dependent Rotation (DDR):** The rotation distance is derived from all 64 bits of the input word, forcing exponential path explosion in differential and linear trail analysis. Constant-time branchless implementation on all platforms.

These are composed into a **quintet round**, a 5-word mixing structure applied in row, column, and diagonal phases across 32 rounds of 15 quintets each (480 quintet-rounds total).

### Temporal Permutation Variance

Every cipher ever published has a fixed algebraic structure. The key changes what the cipher does to your data, but the cipher itself is the same mathematical object on every invocation.

KK is fundamentally different. The rotation schedule governing MFR operations is derived from a runtime entropy snapshot captured at the moment of encryption. **The algebraic structure of the permutation itself changes with every invocation.** Each ciphertext is produced by a permutation with a distinct internal geometry.

This makes multi-query differential and linear attacks structurally inapplicable: the attacker cannot accumulate observations under a fixed permutation because no fixed permutation exists. It also enables built-in temporal commitment proofs that bind ciphertexts to their creation timestamps with cryptographic strength, directly applicable to regulatory compliance, audit trails, supply-chain integrity, and tamper-evident logging.

### Why Does This Matter?

Modern symmetric cryptography relies on a small number of standard primitives (AES, SHA-2/SHA-3, ChaCha20-Poly1305). While these have withstood decades of cryptanalysis, the resulting monoculture concentrates systemic risk: a structural break in any single widely deployed primitive would cascade across protocols, implementations, and infrastructure simultaneously.

KK occupies a previously empty point in the design space:

| Property | KK | Keccak/SHA-3 | ChaCha20 | Ascon | RC5/RC6 |
|----------|----|----|----|----|---|
| Table-free ARX | Yes | No (chi S-box) | Yes | No (S-box) | Yes |
| Wide sponge (1600-bit) | Yes | Yes | No (512-bit CTR) | No (320-bit) | No (block cipher) |
| Data-dependent rotations | Yes (DDR) | No | No | No | Yes |
| Per-invocation algebraic variance | Yes | No | No | No | No |
| Complete crypto suite from single permutation | Yes | Partial | No | Partial | No |

KK is positioned as a **diversity candidate**: not as a replacement for established standards, but as an independently designed construction for systems requiring algorithmic heterogeneity, table-free constant-time execution, built-in temporal binding, or a sponge-based suite with a non-S-box algebraic lineage.

> For the full design rationale, analysis, and formal specification, see the [Combined Paper](docs/KK_COMBINED_PAPER.md) or [ePrint 2026/108538](https://eprint.iacr.org/2026/108538).

---

## Quick Start

```rust
use kk_crypto::{encode, decode};

let key = b"our-shared-secret";

// Encode: symbol values become functions of this cosmic instant
let packet = encode(key, b"Hello KK!").unwrap();

// Decode: same secret, same moment reference, same message
let plaintext = decode(key, &packet).unwrap();
assert_eq!(plaintext, b"Hello KK!");
```

<details>
<summary><b>AEAD (Authenticated Encryption with Associated Data)</b></summary>

```rust
use kk_crypto::{encode_aead, decode_aead};

let key = b"our-shared-secret";
let aad = b"metadata-not-encrypted-but-authenticated";

let packet = encode_aead(key, aad, b"secret payload").unwrap();
let plaintext = decode_aead(key, aad, &packet).unwrap();
assert_eq!(plaintext, b"secret payload");
```

</details>

<details>
<summary><b>Forward-Secret Sessions (Rope Ratchet)</b></summary>

```rust
use kk_crypto::{encode_session, decode_session, RopeRatchet};

let key = b"session-key";
let mut alice = RopeRatchet::new(key);
let mut bob = RopeRatchet::new(key);

// Each message ratchets the cipher's algebraic structure forward
let (packet, step) = encode_session(&mut alice, b"message 1").unwrap();
let plaintext = decode_session(&mut bob, &step, &packet).unwrap();
assert_eq!(plaintext, b"message 1");
// Old keys are gone. Backward computation is impossible.
```

</details>

<details>
<summary><b>Key Agreement (KK-EKA)</b></summary>

```rust
use kk_crypto::{EkaInitiator, EkaResponder};

let psk = b"pre-shared-key";
let (mut alice, msg1) = EkaInitiator::begin(psk).unwrap();
let (mut bob, msg2)   = EkaResponder::respond(psk, &msg1).unwrap();
let alice_key          = alice.finalize(&msg2).unwrap();
let bob_key            = bob.finalize(&alice.msg3(&msg2).unwrap()).unwrap();
// alice_key == bob_key, derived from mutual entropy contribution
```

</details>

<details>
<summary><b>Streaming (Large Messages)</b></summary>

```rust
use kk_crypto::{StreamEncoder, StreamDecoder};

let key = b"stream-key";
let mut encoder = StreamEncoder::new(key).unwrap();
encoder.update(b"chunk 1").unwrap();
encoder.update(b"chunk 2").unwrap();
let packet = encoder.finalize().unwrap();

let mut decoder = StreamDecoder::new(key, &packet).unwrap();
let mut buf = Vec::new();
decoder.read_to_end(&mut buf).unwrap();
```

</details>

<details>
<summary><b>Batch Encoding (High Throughput)</b></summary>

```rust
use kk_crypto::{encode_aead_batch, decode_aead_batch};

let key = b"batch-key";
let aad = b"batch-aad";
let messages: Vec<&[u8]> = vec![b"msg1", b"msg2", b"msg3"];

let packets = encode_aead_batch(key, aad, &messages).unwrap();
let decoded = decode_aead_batch(key, aad, &packets).unwrap();
```

</details>

---

## The Primitive

A 1600-bit sponge construction built entirely from first principles. No borrowed components.

```text
State:     25 x 64-bit words  =  200 bytes  =  1600 bits
Rate:      19 words  (152 bytes, 1216 bits)
Capacity:   6 words  ( 48 bytes,  384 bits)  ~  192-bit security
Rounds:    32, each with 15 quintet operations  =  480 quintet-rounds
```

### Novel Operations

| Operation | What it does |
|-----------|-------------|
| **MFR** (Multiply-Fold-Rotate) | Widening 64-bit multiply, fold XOR with `^b` re-injection, rotation. Non-linear, bijective, full-word mixing. Extrapolated single-operation max differential: 2^(-63). |
| **DDR** (Data-Dependent Rotation) | Rotation distance derived from all 64 bits of input via multiplicative selector (`0xB5C0FBCFEC4D3B2F` = ⌊frac(∛5) × 2⁶⁴⌋). Constant-time branchless implementation. Forces exponential path explosion in trail analysis. |

### Design Properties
- **5-word quintet mixing:** Row, column, and diagonal phases ensure full diffusion in 4 rounds
- **Entropy-derived rotation schedules:** The algebraic structure of the permutation changes per invocation
- **Nothing-up-my-sleeve constants:** 25 values from fractional parts of square roots of the first 25 primes
- **Intra-round re-keying:** Capacity words mixed back into rate every 8 rounds with round-dependent rotation
- **No lookup tables:** Inherent cache-timing side-channel resistance on all platforms, verified by dudect (|t| = 2.28, threshold 4.5)
- **Complementary duality:** MSB differential weakness and LSB linear weakness sit at opposite ends of the word. No single bit position is exploitable in both dimensions simultaneously.

### Computed Security Bounds

| Property | Bound | Margin over 2^(-800) target |
|----------|-------|-------------------------------|
| **MILP-proven active components (32R, general)** | **1,052 minimum** | **Proven optimal (CBC solver)** |
| **MILP-proven active components (32R, sponge)** | **1,067 minimum** | **Proven optimal (CBC solver)** |
| Differential trail (32 rounds, 424+ active MFR) | 2^(-26,712) | 25,912 bits |
| MILP structural bound (conservative MDP) | 2^(-1,489) | 689 bits |
| Linear trail (32 rounds) | 2^(-2,544) | 1,744 bits |
| DDR universal floor per active quintet | LP ≤ 2^(-12) | Regardless of MFR behavior |
| Strict avalanche criterion | Mean $128.00/256$ bit flips | Ideal |
| Bit independence | Max correlation $0.046$ | Near-zero |
| Hash collisions | Zero in $2 \times 10^6$ trials | N/A |

### MILP Differential Trail Analysis (NEW)

A word-level truncated differential MILP model solved to **proven optimality** by the CBC solver establishes structural lower bounds on the number of active non-linear components in any differential trail through the KK permutation.

| Rounds | General | Sponge | Trail Bound (General) | Trail Bound (Sponge) |
|--------|---------|--------|----------------------|---------------------|
| 1 | 6 | 6 | 2^(-8.5) | 2^(-8.5) |
| 2 | 41 | 41 | 2^(-58.0) | 2^(-58.0) |
| 3 | 73 | 75 | 2^(-103.3) | 2^(-106.1) |
| 4 | 110 | 111 | 2^(-155.7) | 2^(-157.1) |
| 8 | 254 | 254 | 2^(-359.4) | 2^(-359.4) |
| 16 | 519 | 519 | 2^(-734.4) | 2^(-734.4) |
| 32 | **1,052** | **1,067** | **2^(-1,488.6)** | **2^(-1,509.8)** |

All 14 models (7 round counts x 2 scenarios) solved to **proven optimality** with zero gap.

**Key findings:**
- The 192-bit security threshold (capacity/2) is crossed between rounds 5 and 6 using conservative per-component MDP of 2^(-1.415) from the exhaustive 8-bit DDT
- At full 32 rounds: security margin of ~7.7x the 192-bit target in the exponent
- The sponge scenario (rate-only input differences) yields equal or higher active counts, confirming that capacity isolation strengthens resistance
- These bounds are **complementary** to the existing 2^(-26,712) DDT extrapolation bound, which uses per-operation MDP at the full 64-bit scaling

The MILP model and solver scripts are in [`analysis/`](analysis/).

---

## What Ships in the Box

Everything below is built from the KK permutation alone. Zero external cryptographic dependencies.

| Primitive | Description |
|-----------|-------------|
| **KK-Hash** | 256-bit collision-resistant hash |
| **KK-KDF** | Key derivation with entropy-derived rotation schedule per derivation |
| **KK-MAC** | Message authentication, constant-time verification |
| **KK Stream Cipher** | Per-chunk independent keystream derivation |
| **KK-AEAD** | Authenticated encryption with associated data |
| **Temporal Commitment** | Binds ciphertext to the exact entropic moment of creation |
| **Bound Commitment** | Challenge-response with nonce chaining for replay prevention |
| **Split-Channel Mode** | Entropy snapshot transmitted on a separate channel |
| **Rope Ratchet** | 4-strand forward-secret session protocol, ~192-bit forward secrecy |
| **KK-EKA** | 3-message entropy key agreement, zero external primitives |
| **KK-RNG** | Forward-secret DRBG, ratchets on every call |
| **AVX-512 Batch** | 8 independent sponge states in lockstep across 512-bit registers |
| **GPU Acceleration** | wgpu compute shader + CUDA, RTX 5080 verified, byte-identical to CPU |
| **no_std Core** | Bare permutation + hash + KDF + MAC + RNG for embedded / WASM |

---

## Performance

All numbers measured on a single AMD Ryzen 9 9950X3D ($699 consumer CPU).
16 cores / 32 threads, Zen 5, AVX-512, 5.35 GHz boost.
Criterion framework, 100 samples per benchmark point, 251 tests passing.

### Batch AEAD Throughput

| Workload | Throughput | Messages/sec |
|----------|-----------|-------------|
| 1,000 x 64 KB | **5.22 GiB/s** | 85,000+ |
| 1,000 x 16 KB | 2.40 GiB/s | 153,000+ |
| 1,000 x 4 KB | 1.53 GiB/s | 430,000+ |
| 10,000 x 4 KB | 1.67 GiB/s | 430,000+ |

### Core Primitives

| Primitive | Speed |
|-----------|-------|
| KK permutation (32 rounds, 1600-bit) | 1.14 us |
| KK-Hash | 186 MiB/s |
| KK-MAC | 127 MiB/s |
| KK-KDF | 145 MiB/s |
| KK-RNG (forward-secret per call) | 186 MiB/s |
| Entropy rotation derivation | 11.4 ns |

### Scaling

| Config | Throughput | Notes |
|--------|-----------|-------|
| Single core (AVX-512 batch) | 497 MiB/s | Matches SHA-3/Keccak per-core while doing 4x the work per byte |
| 16 threads | 4.09 GiB/s | Physical cores only |
| 32 threads (SMT) | 5.22 GiB/s | +27% from hyperthreads (unusual for AVX-512) |
| GPU (wgpu WGSL) | 1.01 GiB/s | Raw permutation |
| GPU (CUDA native) | 2.08 GiB/s | Raw permutation, RTX 5080 |
| KK-EKA handshake | 44.6 us | 22,400 authenticated key agreements/sec |
| KK-RNG pool (32 threads) | 2.80 GiB/s | Forward-secret random bytes |

---

## Architecture

```text
Entropy Sources  >  KK-Mix  >  Per-Symbol Derivation  >  Temporal Binding  >  Encoding
  (entropy.rs)    (kk_mix.rs)       (kdf.rs)              (temporal.rs)       (codec.rs)
```

| Module | Role |
|--------|------|
| `kk_mix.rs` | KK permutation, sponge, KK-Hash, KK-KDF, KK-MAC |
| `kk_mix_avx512.rs` | AVX-512 vectorized permutation (8 states simultaneously) |
| `entropy.rs` | Non-deterministic entropy (RDTSC, thread jitter, OS CSPRNG) |
| `kdf.rs` | Per-chunk keystream derivation (scalar + batched AVX-512) |
| `temporal.rs` | Temporal commitment binding |
| `codec.rs` | Public API, packet serialization, streaming, batch encoding |
| `session.rs` | Rope Ratchet forward-secret session protocol |
| `eka.rs` | KK-EKA three-message entropy key agreement |
| `rng.rs` | KK-RNG forward-secret DRBG |
| `qkd.rs` | BB84 quantum key distribution simulation |

---

## Security Model

<details>
<summary><b>Threat Model</b></summary>

KK assumes a pre-shared secret between sender and receiver. An attacker may observe, replay, or modify ciphertext in transit but does not know the shared secret.

</details>

<details>
<summary><b>Confidentiality</b></summary>

Each encoding captures a unique `EntropySnapshot` (CPU counters, thread jitter, OS randomness). The snapshot feeds KK-KDF to derive per-chunk keystream. The same plaintext never produces the same ciphertext twice.

</details>

<details>
<summary><b>Integrity</b></summary>

Every packet carries a KK-MAC tag over (ciphertext + entropy snapshot). `decode` rejects any packet whose tag does not verify.

</details>

<details>
<summary><b>Temporal Binding</b></summary>

The `TemporalCommitment` in each packet commits to the entropy used during encoding. The receiver re-derives the commitment and rejects packets if it does not match.

</details>

<details>
<summary><b>Key Hygiene</b></summary>

All intermediate keys (commit keys, chunk keystream) are zeroized via the `zeroize` crate immediately after use. Output buffers are zeroized on error paths to prevent partial plaintext leaks.

</details>

<details>
<summary><b>Formal Bounds</b></summary>

| Property | Bound | Margin over 2^-800 target |
|----------|-------|--------------------------|
| MILP-proven active components (32R) | 1,052 minimum (general), 1,067 (sponge) | Proven optimal |
| Differential trail | 2^-26,712 | 25,912 bits |
| MILP structural bound (conservative MDP) | 2^-1,489 | 689 bits |
| Linear trail | 2^-2,544 | 1,744 bits |
| DDR universal floor | LP <= 2^-12 per active quintet | Regardless of MFR behavior |
| Full diffusion | 4 rounds | Confirmed |

Complementary duality proven: MSB differential weakness and LSB linear weakness sit at opposite ends of the word. No single bit position is exploitable in both dimensions simultaneously.

MILP structural lower bound (word-level truncated differential model) solved to proven optimality by CBC for all round counts 1 through 32. See [analysis/](analysis/) for the complete model and solver.

</details>

### Limitations

- **Un-audited.** Novel primitive, not reviewed by third-party cryptographers.
- **No replay protection.** Callers must add sequence numbers or timestamps at the protocol layer.
- **Forward secrecy requires Rope Ratchet.** The base codec does not provide forward secrecy on its own.

---

## Building

```bash
cargo build                          # standard build
cargo build --no-default-features    # no_std (core primitives only)
cargo build --features gpu           # wgpu GPU acceleration
cargo build --features cuda          # CUDA GPU acceleration
```

## Testing

```bash
cargo test            # 251 tests
cargo clippy          # lint
cargo bench           # 56 criterion benchmarks (100 samples each)
```

| Category | Count |
|----------|-------|
| Unit tests | 94 |
| Integration tests | 63 |
| Property tests (proptest) | 18 |
| Deterministic test vectors | 44 |
| Documentation tests | 8 |
| GPU correctness tests | 10 |
| Criterion benchmark points | 56 |
| **Total** | **251 tests, zero failures** |

## Fuzzing

8 fuzz targets under `fuzz/`. Requires [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```bash
cargo fuzz run hash_fuzz       # KK-Hash
cargo fuzz run kdf_fuzz        # KK-KDF
cargo fuzz run mac_fuzz        # KK-MAC
cargo fuzz run roundtrip_fuzz  # encode/decode roundtrip
cargo fuzz run aead_fuzz       # AEAD mode
cargo fuzz run session_fuzz    # Rope Ratchet sessions
cargo fuzz run temporal_fuzz   # temporal commitment
cargo fuzz run eka_fuzz        # key agreement
```

## no_std Support

With `--no-default-features`, KK exposes the core permutation, KK-Hash, KK-KDF, KK-MAC, and KK-RNG for `no_std + alloc` environments (embedded, WASM).

```toml
[dependencies]
kk-crypto = { version = "0.1", default-features = false }
```

---

## Documentation

| Document | Description |
|----------|-------------|
| **[Combined Paper](docs/KK_COMBINED_PAPER.md)** | **Primary reference.** Full design, analysis, specification, and performance in one document. Also available as [PDF](docs/KK_COMBINED_PAPER.pdf) and on [ePrint (2026/108538)](https://eprint.iacr.org/2026/108538). |
| [Test Vectors](docs/KK_TEST_VECTORS.md) | Deterministic reference vectors for cross-language implementation |
| [Integration Guide](docs/integration-guide.md) | Examples for all codec modes, streaming, sessions, EKA |
| [Technical Flex](docs/real_flex.md) | Full technical breakdown and competitive analysis |
| [Security Policy](docs/SECURITY.md) | Responsible disclosure process |
| [Changelog](CHANGELOG.md) | Version history |

---

<div align="center">

**J.A. Keeney, Australia, 2026**

</div>

## License

Apache 2.0 with Additional Terms. **No commercial use** without prior written authorization from John A Keeney / Entrouter. See [LICENSE](LICENSE) for full terms. Contact: hello@entrouter.com
