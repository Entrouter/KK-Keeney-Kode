# Changelog

All notable changes to KK-Crypto will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.2] - 2026-03-26

### Fixed
- ePrint reference number corrected from 108500 to 108538 in README badge and body text.
- Documentation table updated (Combined Paper replaces old Specification/Whitepaper entries) so crates.io displays current docs.

## [Unreleased]

### Added
- **Streaming API:** `StreamEncoder` and `StreamDecoder` for incremental encode/decode of large messages.
- **no_std support:** Feature-gated `std` (default). With `--no-default-features`, the `kk_mix` core (hash, KDF, MAC) is available in `no_std + alloc` environments.
- **Property-based tests:** 18 proptest properties covering roundtrip identity, determinism, forgery detection, key sensitivity, length preservation, session ratcheting, and temporal binding.
- **Expanded fuzz targets:** `aead_fuzz`, `session_fuzz`, `temporal_fuzz`, `eka_fuzz` (8 total).
- **CI/CD pipeline:** GitHub Actions workflows for fmt, clippy, test (stable+nightly matrix), docs, security audit, fuzz, coverage, and no_std build.
- **Security policy:** `SECURITY.md` with responsible disclosure process.
- **cargo-deny config:** `deny.toml` for license and advisory checks.
- **Coverage workflow:** Tarpaulin → Codecov integration.
- **Comprehensive benchmark suite:** 56 benchmark points across 6 groups (core primitives, AEAD codec, split codec, bound codec, session/key agreement, temporal/entropy) using Criterion framework. Peak hash throughput ~127 MiB/s; EKA handshake 44.6 µs (~22,400/sec); all 3 codec modes at identical performance; sub-100 ns packet serde.
- **AVX-512 vs scalar benchmark:** `bench_avx512_vs_scalar` comparing sequential 8× `kk_kdf` against `kk_kdf_batch_8` at 32 B/64 B/256 B output sizes.

### Changed
- `rayon`, `rand`, and `thiserror` are now optional dependencies, pulled in by the `std` feature (enabled by default).
- AVX-512 vectorized paths gated behind `std` feature (requires `is_x86_feature_detected!`).
- **Documentation consolidation:** Merged KK_X_PUBLICATION.md and KK_CRYPTO_EMPIRICAL_ANALYSIS.md into unified KK_WHITEPAPER.md. Removed IMPLEMENTATION_PLAN.md and todo.md.

## [0.1.0] - 2026-01-01

### Added
- KK permutation v2 (Multiply-Fold-Rotate + Data-Dependent Rotation on 1600-bit state).
- KK-Hash (256-bit), KK-KDF (arbitrary length), KK-MAC (256-bit).
- Entropy collection: RDTSC, thread jitter, OS RNG.
- Temporal commitment binding.
- Four codec modes: basic, split, bound (temporal), AEAD.
- Session module with Rope Ratchet (~192-bit forward secrecy).
- KK-EKA (Entropy Key Agreement) three-message handshake.
- BB84 QKD simulation.
- AVX-512 vectorized 8-way batch KDF.
- Deterministic test vectors (170+ tests).
- Benchmark suite (criterion).
- Initial fuzz targets: `hash_fuzz`, `kdf_fuzz`, `mac_fuzz`, `roundtrip_fuzz`.
