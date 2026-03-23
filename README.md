<!--
Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
Licensed under the Apache License, Version 2.0 with Additional Terms.
NO COMMERCIAL USE without prior written authorization from Entrouter.
Unauthorized commercial use will be prosecuted to the fullest extent of the law.
See the LICENSE file in the project root for full license information.
NOTICE: Removal of this header is a violation of the license.
-->

# KK, Keeney Kode

[![CI](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/ci.yml/badge.svg)](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/ci.yml)
[![Security](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/security.yml/badge.svg)](https://github.com/Entrouter/KK-Keeney-Kode/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A novel cryptographic primitive where symbol values are temporal functions of universal entropy.

## Core Principle

In all existing cryptography, symbol 'A' has a fixed value and encryption hides what 'A' means.
In KK, symbol 'A' has no fixed value, its value is a function of the universe at the instant it was born.
The same symbol encoded twice produces two cryptographically unrelated values.

## Quick Start

```rust
use kk_crypto::{encode, decode};

let shared_secret = b"our-shared-secret";

// Encode: symbol values become functions of this cosmic instant
let packet = encode(shared_secret, b"Hello KK!").unwrap();

// Decode: same secret, same moment reference, same values
let plaintext = decode(shared_secret, &packet).unwrap();
assert_eq!(plaintext, b"Hello KK!");
```

## Architecture

```text
Entropy Sources → KK-Mix → Per-Symbol Derivation → Temporal Binding → Encoding
    (entropy.rs)  (kk_mix.rs)    (kdf.rs)            (temporal.rs)     (codec.rs)
```

Every cryptographic operation is built from a single novel primitive:
the **KK permutation** (Multiply-Fold-Rotate sponge construction on a 1600-bit / 5×5×64 state).
No SHA-256, no HKDF, no HMAC, 100% original KK.

| Module | Role |
|--------|------|
| `entropy.rs` | Gathers non-deterministic entropy (RDTSC, thread jitter, OS RNG) |
| `kk_mix.rs` | KK permutation, sponge, KK-Hash, KK-KDF, KK-MAC |
| `kk_mix_avx512.rs` | AVX-512 vectorized permutation (8 states simultaneously) |
| `kdf.rs` | Per-chunk keystream derivation (scalar + batched AVX-512) |
| `temporal.rs` | Temporal commitment (binds ciphertext to entropy snapshot) |
| `codec.rs` | Public `encode`/`decode` API, packet serialization, streaming API |
| `session.rs` | Rope Ratchet forward-secret session encoding |
| `eka.rs` | KK-EKA three-message entropy key agreement |
| `qkd.rs` | BB84 quantum key distribution simulation |

## Security Model

**Threat model:** KK assumes a pre-shared secret between sender and receiver.
An attacker may observe, replay, or modify ciphertext in transit but does not know the shared secret.

**Confidentiality:** Each encoding captures a unique `EntropySnapshot` (CPU counters, thread jitter, OS randomness).
The snapshot feeds the KK-KDF to derive per-chunk keystream, ensuring the same plaintext never produces the same ciphertext twice.

**Integrity:** Every `KkPacket` carries a KK-MAC tag over (ciphertext ‖ entropy snapshot).
`decode` rejects any packet whose tag does not verify, preventing silent tampering.

**Temporal binding:** The `TemporalCommitment` in each packet commits to the entropy used during encoding.
The receiver re-derives the commitment from the embedded snapshot and the shared secret, rejecting packets if the commitment does not match.

**Key hygiene:** Intermediate keys (commit keys, chunk keystream) are zeroized via the `zeroize` crate immediately after use.
The output buffer is zeroized on error paths to prevent partial plaintext leaks.

### Limitations

- **Un-audited:** KK is a novel primitive, it has **not** been reviewed by third-party cryptographers. Do not use for production security.
- **Forward secrecy via Rope Ratchet:** The session module provides ~192-bit forward secrecy through a 4-strand ratchet. Compromise of a single session key does not expose past or future messages.
- **No replay protection:** Callers must add sequence numbers or timestamps at the protocol layer.

## Building & Testing

```bash
cargo build
cargo test
cargo clippy

# no_std build (exposes kk_mix core only)
cargo build --no-default-features
```

## Fuzzing

Fuzz targets are under `fuzz/`. Requires [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```bash
cargo fuzz run hash_fuzz
cargo fuzz run kdf_fuzz
cargo fuzz run mac_fuzz
cargo fuzz run roundtrip_fuzz
cargo fuzz run aead_fuzz
cargo fuzz run session_fuzz
cargo fuzz run temporal_fuzz
cargo fuzz run eka_fuzz
```

## Documentation

- [Whitepaper](docs/KK_WHITEPAPER.md) - complete design specification, empirical analysis & performance benchmarks
- [Integration Guide](docs/integration-guide.md) - examples for all codec modes, streaming, sessions, EKA
- [Changelog](CHANGELOG.md)
- [Security Policy](docs/SECURITY.md)

## License

Apache 2.0 with Additional Terms - NO COMMERCIAL USE without prior written authorization from John A Keeney / Entrouter. See [LICENSE](LICENSE) for details.
