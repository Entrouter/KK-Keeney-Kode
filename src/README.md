<!--
Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
Licensed under the Apache License, Version 2.0 with Additional Terms.
NO COMMERCIAL USE without prior written authorization from Entrouter.
Unauthorized commercial use will be prosecuted to the fullest extent of the law.
See the LICENSE file in the project root for full license information.
NOTICE: Removal of this header is a violation of the license.
-->

# KK-Crypto  - Source Overview

This directory contains the core Rust modules that make up the KK cryptographic system.

## Module Map

| Module | Description |
|--------|-------------|
| `kk_mix.rs` | **Core primitive.** The KK permutation (1600-bit, 5×5 grid), sponge construction, and all derived functions: `kk_hash`, `kk_kdf`, `kk_mac`, `kk_kdf_batch_8`. Always available (including `no_std`). |
| `kk_mix_avx512.rs` | AVX-512 vectorized kernel  - processes 8 sponge states in parallel. Used by `kk_kdf_batch_8` when the CPU supports AVX-512F+DQ. x86_64 + `std` only. |
| `codec.rs` | Public encode/decode API with 4 modes (Basic, Authenticated/AEAD, Temporal, Session) plus `StreamEncoder`/`StreamDecoder` for incremental processing. |
| `entropy.rs` | `EntropySnapshot`  - captures system entropy (timestamps, thread IDs, counters) at the moment of encoding. |
| `temporal.rs` | `TemporalProof` / `TemporalCommitment`  - proves data existed at a specific point in time. |
| `session.rs` | `RopeRatchet`  - a novel double-strand ratchet for session key evolution. Supports `encode_session` / `decode_session`. |
| `eka.rs` | KK-EKA (Entropic Key Agreement)  - a Diffie-Hellman-like handshake built entirely from the KK permutation. |
| `kdf.rs` | Higher-level key derivation helpers that wrap `kk_kdf`. |
| `qkd.rs` | BB84-style quantum key distribution simulation. |
| `error.rs` | `KkError` enum  - all failure modes for the crate. |

## Architecture

```
  User API (codec.rs)
     │
     ├── entropy.rs ─── gathers system entropy
     ├── temporal.rs ── time-binding proofs
     ├── session.rs ─── ratchet-based sessions
     ├── eka.rs ─────── key agreement handshake
     │
     └── kk_mix.rs ──── core permutation + sponge
            │
            └── kk_mix_avx512.rs (optional SIMD acceleration)
```

All cryptographic operations ultimately flow through `kk_mix.rs`. The sponge absorbs keying material and entropy, then squeezes output. `kk_mix_avx512.rs` accelerates the squeeze phase for batch operations.

## Running Examples

```bash
cargo run --example proof       # Formal verification proofs
cargo run --example visual      # Visual diff  - each encoding is unique
cargo run --example split_demo  # Packet structure inspection
cargo run --example basic       # Basic encode/decode roundtrip
cargo run --example qkd_demo    # QKD simulation
```

## Feature Flags

- **`std`** (default)  - Enables all modules. Requires `rand`, `rayon`, `thiserror`.
- **`no_std`** (`--no-default-features`)  - Exposes only `kk_mix` with `alloc`. For embedded targets.