# KK (Keeney Kode): The Complete Technical Flex

**John A Keeney | Entrouter | Australia | 2026**


## THE PRIMITIVE

Novel 1600-bit sponge construction built entirely from first principles. No SHA. No AES. No borrowed S-boxes. No external primitives. Every operation, every constant, every round function purpose-built from scratch.

**KK(S) = S XOR E: state XOR universal entropy at the precise instant of creation.**

- 5x5 grid of 64-bit words: 25 words, 200 bytes of state, 1600 bits
- Rate: 1216 bits (152 bytes), 19 words
- Capacity: 384 bits (48 bytes), 6 words
- ~192-bit security against generic sponge attacks
- 32 rounds of 15 quintet operations each
- 480 quintet-rounds per permutation: 960 MFR + 480 DDR operations total

Two novel operations nobody else has:

- **MFR (Multiply-Fold-Rotate):** widening 64-bit multiply, fold XOR, fixed rotation. Non-linear, bijective, full-word mixing.
- **DDR (Data-Dependent Rotation):** rotation distance derived from all 64 bits of input. Constant-time branchless 6-step implementation. No published cipher uses this. No published analysis framework efficiently handles it.

Additional design features:

- Novel 5-word quintet mixing structure: no published cipher uses 5-word rounds
- Entropy-derived rotation schedules: the algebraic structure of the permutation changes per invocation. Not different data through the same algorithm. A different algorithm entirely at each moment.
- Nothing-up-my-sleeve IV: 25 constants derived from fractional parts of square roots of the first 25 primes. Independently verifiable by anyone.
- Intra-round re-keying every 8 rounds: capacity words mixed back into rate with round-dependent rotation, breaking fixed-structure analysis


## THE COMPLETE CRYPTOSYSTEM: ONE PRIMITIVE, EVERYTHING

Every operation below is built from the KK permutation alone. Zero external dependencies. Zero borrowed code. Zero external libraries.

| Primitive | Description |
|-----------|-------------|
| **KK-Hash** | 256-bit collision-resistant hash |
| **KK-KDF** | Key derivation with entropy-derived rotation schedule per derivation |
| **KK-KDF Batch** | 8 independent KDFs in one AVX-512 SIMD pass |
| **KK-MAC** | Message authentication code, constant-time verification |
| **KK-MAC Batch** | 8 simultaneous MACs in one AVX-512 SIMD pass, zero-copy architecture |
| **KK Stream Cipher** | Entropy-derived keystream, per-chunk independent derivation |
| **KK-AEAD** | Authenticated encryption with associated data, AAD binding prevents transplant attacks |
| **Temporal Commitment** | Binds ciphertext to the exact entropic moment of creation |
| **Bound Commitment** | Challenge-response with nonce chaining, replay prevention |
| **Split-Channel Mode** | Entropy snapshot transmitted on separate channel |
| **Rope Ratchet** | 4-strand forward-secret session protocol, ~192-bit forward secrecy |
| **KK-EKA** | 3-message entropy key agreement protocol, zero external primitive |
| **KK-RNG** | Forward-secret deterministic random bit generator, ratchets on every call |
| **GPU Acceleration** | wgpu compute shader + CUDA implementation, RTX 5080 verified |
| **no_std Embedded** | Bare permutation + hash + KDF + MAC + RNG for embedded/WASM |


## SECURITY PROPERTIES

- Each encoding is a unique cryptographic event: same plaintext, same key, one nanosecond apart = two cryptographically unrelated ciphertexts
- No classical known-ciphertext attack: attacker cannot accumulate knowledge across encodings because each used a structurally different cipher
- ~192-bit security against generic sponge attacks (384-bit capacity)
- Forward secrecy via Rope Ratchet: compromise of long-term key reveals nothing about past sessions
- Mutual authentication via KK-EKA: both parties prove knowledge of PSK
- Contributory key agreement: neither party alone controls the session key
- Commitment binding: Alice commits entropy before seeing Bob's, preventing adaptive selection
- Temporal freshness: nanosecond timestamps in entropy snapshots
- AEAD tamper detection: modification of either ciphertext OR associated data fails authentication
- Constant-time throughout: MAC verify, KDF, all operations verified timing-safe via dudect
- Full zeroization: all ephemeral keys, message keys, intermediate values zeroized immediately after use via the zeroize crate
- 4 independent entropy sources mixed per snapshot: OS CSPRNG, system timestamp, CPU RDTSC counter, thread jitter measurement
- Domain separation: hash/KDF/MAC/session all separated by domain bytes preventing cross-protocol attacks
- Length-prefix protection: all inputs length-prefixed preventing canonicalization attacks
- Verify-before-decrypt: integrity checked before any plaintext produced, preventing partial plaintext leaks


## EMPIRICAL SECURITY ANALYSIS: ALL TESTS PASS

10 independent test categories:

| # | Test | Result |
|---|------|--------|
| 1 | Constant-time execution (dudect Welch t-test, 5 scenarios) | No timing leak detected |
| 2 | Perfect diffusion (SAC mean) | Exactly 128.00/256: textbook perfect |
| 3 | Bit independence (BIC max correlation) | 0.046: excellent |
| 4 | Collision resistance | Zero collisions in 2,000,000 adversarial inputs |
| 5 | Length-extension resistance | Complete, from sponge construction |
| 6 | Statistical uniformity | Chi-squared goodness-of-fit confirmed |
| 7 | Known-answer tests | Stable deterministic output against frozen reference vectors |
| 8 | Differential trail analysis (6 tests) | No exploitable trail found |
| 9 | Linear cryptanalysis (7 tests) | All biases at statistical noise floor |
| 10 | Algebraic degree | MFR >= 24, quintet round >= 20, full permutation >= 22 from round 1 |


## FORMAL CRYPTANALYTIC BOUNDS

- **Differential trail bound:** 2^-26,712. Security margin of 25,912 bits above the 2^-800 target.
- **Linear trail bound:** 2^-2,544. Security margin of 1,744 bits above the 2^-800 target.
- **Complementary duality proven:** MSB differential weakness and LSB linear weakness sit at OPPOSITE ends of the word. No single bit position is exploitable in both dimensions simultaneously. 4/4 theorems verified constructively at 8-bit (exhaustive), 16-bit (exhaustive), 32-bit (sampled).
- **DDR universal floor:** LP <= 2^-12 per active quintet regardless of MFR behavior.
- **Formal DDT:** exhaustive at 8-bit and 16-bit via Walsh-Hadamard Transform.
- **Formal LAT:** exhaustive at 8-bit and 16-bit.
- **Full diffusion** in 4 rounds confirmed.
- **MFR per-bit MDP** scales at exactly -1.0 per word-size bit: verified exhaustively.
- **DDR forces exponential path explosion:** no published analysis framework efficiently handles DDR.


## THE ROPE RATCHET: FORWARD SECRECY

- 4-strand ratchet: entropy strand, temporal strand, chain strand, counter strand
- Per-message algebraic structure rotation: not just the key changes, the cipher's mathematical structure changes with every message. Signal's Double Ratchet only changes the key.
- ~192-bit forward secrecy from 384-bit sponge capacity
- Double entropy: ratchet step uses one entropy snapshot for key derivation, inner packet captures its own independent snapshot. Two unrepeatable moments per message.
- Strict counter ordering: replay and reorder attacks impossible
- Irrecoverable state: old chain strand overwritten, backward computation impossible
- Potentually Stronger than Signal's Double Ratchet in security margin and structural novelty


## KK-EKA: KEY AGREEMENT

- 3-message protocol built entirely from KK primitives
- Zero external primitive: no Curve25519, no HMAC, no HKDF, nothing external
- Mutual authentication via KK-MAC
- Contributory: neither party controls the session key alone
- Forward secrecy: ephemeral entropy zeroized after derivation
- Commitment binding: prevents adaptive entropy selection
- Channel agnostic: works over TCP, WebSocket, carrier pigeon. Authenticated via MAC, channel doesn't need to be secure.
- Direct integration: session key feeds directly into RopeRatchet::new()
- 22,400 complete authenticated key agreements per second on a single $699 consumer CPU


## PERFORMANCE (REAL, MEASURED, CRITERION FRAMEWORK)

### Hardware

All numbers below measured on a single AMD Ryzen 9 9950X3D: a $699 USD consumer desktop CPU. 16 cores / 32 threads, Zen 5, AVX-512, 5.35 GHz boost, 96 GB DDR5-6000. One socket. One node. No cluster. No cloud. No tricks.

### Core Primitives

| Primitive | Throughput |
|-----------|-----------|
| KK permutation | 1.14 us per full 32-round 1600-bit state transform |
| Entropy-derived rotation derivation | 11.4 nanoseconds (essentially free) |
| KK-Hash | 186 MiB/s |
| KK-MAC | 127 MiB/s |
| KK-KDF | 145 MiB/s |
| KK-RNG | 186 MiB/s (forward-secret on every call) |

### Batch AEAD: The Headline Numbers

| Workload | Throughput |
|----------|-----------|
| 1,000 x 64KB messages | **5.22 GiB/s encode** |
| 1,000 x 16KB messages | 2.40 GiB/s encode |
| 1,000 x 4KB messages | 1.53 GiB/s encode |
| 10,000 x 4KB messages | 1.67 GiB/s encode |
| 1,000 x 64KB roundtrip (encode + decode) | 1.37 GiB/s |

**85,000+ authenticated encrypted 64KB messages per second. 430,000+ at 4KB message size.**

### Per Core (Single Core, AVX-512 Batch AEAD)

**497 MiB/s per physical core.**

This matches SHA-3/Keccak per-core throughput while performing 4x the cryptographic work per byte. SHA-3 is JUST a hash function. KK is doing encrypt + MAC + KDF + temporal commitment on every single byte, at the same speed.

### SIMD Architecture

8 independent sponge states running in lockstep across 512-bit registers. Most SIMD crypto parallelizes *within* one message. KK parallelizes *across* 8 messages simultaneously, saturating all 512 bits of every vector register with independent useful work.

The original MFR design used VPMULLQ (6-cycle latency, the most expensive AVX-512 integer instruction). This was engineered away with running accumulators that produce mathematically identical output using VPADDQ (1-cycle). The cipher's algebraic properties are unchanged. The bottleneck was eliminated without touching the algorithm.

### SMT Scaling

Hyperthreads contribute a 27% throughput gain (5.22 GiB/s with 32 threads vs 4.09 GiB/s with 16). This is unusual for AVX-512 workloads where SMT often hurts. KK's implementation is balanced enough that SMT partners usefully fill pipeline bubbles rather than competing for execution ports.

### Zero-Copy MAC

The batch MAC absorbs key and prefix metadata in scalar, then feeds 64KB ciphertext bodies directly into the SIMD pipeline with zero allocation and zero memory copy. 8 x 64KB = 512KB of memcpy eliminated per batch call.

### Key Agreement

| Metric | Value |
|--------|-------|
| Full 3-message KK-EKA handshake | 44.6 us |
| Complete key agreements per second | 22,400 |

### Parallel RNG

32 threads: 2.80 GiB/s of forward-secret cryptographically secure random bytes.

### GPU (RTX 5080 Blackwell)

| Backend | Throughput |
|---------|-----------|
| wgpu WGSL | 1.01 GiB/s raw permutation |
| CUDA native uint64_t | 2.08 GiB/s raw permutation |

10/10 GPU tests pass. Byte-identical to CPU output.


## TEST SUITE

| Category | Count |
|----------|-------|
| Unit tests | 94 |
| Integration tests | 63 |
| Property tests | 18 |
| Deterministic test vectors | 44 (cross-language implementable) |
| Documentation tests | 8 |
| GPU correctness tests | 10 (byte-identical CPU/GPU verification) |
| Criterion benchmark points | 56 (100 samples each) |
| **Total** | **251 tests, zero failures** |


## DOCUMENTATION AND SPECIFICATION

**KK_SPECIFICATION.md:** 1,300+ line formal mathematical specification.

- Every algorithm formally defined with LaTeX notation
- Every input, output, state transition documented
- Every wire format byte-perfect
- Complete appendix cross-referencing every function to exact source line numbers
- Security claims section with formal threat model
- Submittable to standards bodies and competitions

**KK_WHITEPAPER.md:** Complete empirical analysis white paper.

- 40 sections covering design, analysis, performance, assessment
- All results independently reproducible via included example code
- Formal trail bounds with exhaustive verification methodology

**KK_TEST_VECTORS.md:** Deterministic reference vectors.

- Human-readable hex values for all primitives
- Step-by-step intermediate values for hand verification
- Cross-language implementation reference


## IMPLEMENTATION QUALITY

- Pure Rust 2021: memory safe by construction
- Zero unsafe code in cryptographic paths
- AVX-512 SIMD acceleration: 8-wide parallel permutation with automatic runtime detection andscalar   fallback
- Zero-copy batch MAC: no allocation, no memcpy for multi-message authentication
- Constant-time throughout: black_box barriers, no data-dependent branches in security-critical paths
- Full zeroization: zeroize crate on all sensitive material
- no_std compatible: embedded and WASM deployment
- CLI tool: kk-tool hash/mac/rand/enc/dec. Touch the primitive without writing Rust.
- GPU implementation: wgpu (portable) + CUDA (maximum performance)
- Cargo feature flags: gpu feature optional, no_std default clean


## HOW THIS COMPARES TO SIGNAL, WHATSAPP, AND TELEGRAM

### Signal Protocol (used by Signal and WhatsApp)

| Property | Signal Protocol | KK |
|----------|----------------|-----|
| Encryption | AES-256-CBC (encrypt-then-MAC) | KK sponge stream cipher |
| Authentication | HMAC-SHA-256 | KK-MAC (sponge-native) |
| Key agreement | X3DH: 3x X25519 DH + Ed25519 signatures | KK-EKA: 3-message, zero external primitive |
| KDF | HKDF-SHA-256 | KK-KDF (sponge-native, entropy-derived rotation) |
| Hash | SHA-256, SHA-512 | KK-Hash (sponge-native) |
| Ratchet | Double Ratchet: 2 strands (DH chain + symmetric chain) | Rope Ratchet: 4 strands (entropy, temporal, chain, counter) |
| Forward secrecy | ~128-bit (Curve25519) | ~192-bit (384-bit sponge capacity) |
| Per-message structure change | No. Same AES, same SHA. Only the key rotates. | Yes. Entropy-derived rotation schedule changes the cipher's algebraic structure every message. |
| External primitives required | 5: AES, SHA-256, SHA-512, X25519, Ed25519 | 0. Everything from one sponge. |
| Temporal binding | None. No concept of time in the protocol. | Nanosecond entropy snapshot bound to every ciphertext. |
| Designed by | Team at Open Whisper Systems (Moxie Marlinspike et al.) | One person (John A Keeney) |

**Signal's security is well-studied and respected.** But it is an assembly of 5 external primitives from multiple designers. If any one of those primitives breaks (AES, SHA-256, Curve25519), the whole protocol needs emergency surgery. KK has one primitive. One thing to analyze, one thing to trust, one thing to harden.

### Telegram MTProto 2.0

| Property | MTProto 2.0 | KK |
|----------|-------------|-----|
| Encryption | AES-256-IGE (non-standard mode, criticized by cryptographers) | KK sponge stream cipher |
| Authentication | SHA-256 truncated hash check | KK-MAC (constant-time, sponge-native) |
| Key agreement | RSA-2048 server auth + DH-2048 | KK-EKA (zero external primitive) |
| KDF | SHA-256 based, custom construction | KK-KDF (sponge-native) |
| Forward secrecy | Only in "Secret Chats" (opt-in, not default) | Always. Every message. Every mode. |
| E2E encryption | Not default. Group chats are server-decryptable. | Always E2E by construction. |
| Security level | ~112-bit (DH-2048 is the weakest link) | ~192-bit (384-bit sponge capacity) |
| External primitives | 4: AES, SHA-256, RSA, DH | 0 |
| Ratchet | DH re-key in secret chats only, 2-strand | 4-strand Rope Ratchet with structure rotation |
| Temporal binding | Server timestamps (server-controlled, not cryptographic) | Client-side nanosecond entropy snapshot, cryptographically bound |
| Public criticism | Yes. Moxie Marlinspike, Matthew Green, and others have published concerns about IGE mode and the custom protocol design. | Novel, but comes with 1,300-line formal specification, exhaustive differential/linear analysis, and all test infrastructure for independent verification. |

**Telegram chose to invent their own protocol but used standard primitives in non-standard ways (AES-IGE).** They got the worst of both worlds: novelty risk without novelty benefit. KK invents the primitive itself, but does it with formal analysis, exhaustive verification, and a proper specification that can be submitted to competitions.

### The Throughput Gap

| System | Message encryption throughput | Notes |
|--------|------------------------------|-------|
| Signal/WhatsApp | AES-256-GCM: ~3-6 GiB/s with AES-NI | But that is JUST the encryption. MAC, KDF, ratchet step all separate. |
| Telegram | AES-256-IGE: similar AES-NI range | Same caveat. Plus IGE is not parallelizable. |
| KK | **5.22 GiB/s batch AEAD** | Encrypt + MAC + KDF + temporal commitment all fused in one pass. |

Signal and Telegram can quote fast AES numbers but those numbers are just the symmetric cipher in isolation. Add the HMAC pass, add the HKDF derivation, add the ratchet step, and the real per-message cost is significantly higher. KK does all four operations in a single unified pass through the sponge at 5.22 GiB/s. There is no separate MAC pass. There is no separate KDF call. It is all one thing.

At 4KB message sizes (typical for messaging apps), KK processes **430,000+ authenticated encrypted messages per second** on a single $699 consumer CPU. For context, WhatsApp handles roughly 100 billion messages per day globally. That is about 1.16 million messages per second across their entire server fleet. A single KK node covers over a third of WhatsApp's global message volume.


## BUSINESS AND LEGAL



- Apache 2.0 + Section 7 commercial restriction: prior art established, nobody can patent it,       commercial users must contact Entrouter
- Single inventor: John A Keeney, Australia, 2026


## THE ONE LINE SUMMARY

**KK(S) = S XOR E**

XOR with the universe.
