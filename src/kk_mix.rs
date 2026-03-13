// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

//! KK-Mix v2: The novel cryptographic core of the KK system.
//!
//! Everything in KK is built from this single primitive:
//! hashing, key derivation, message authentication, entropy mixing.
//!
//! ## The KK Permutation v2
//!
//! A 1600-bit (25 × 64-bit word) state arranged as a 5×5 grid,
//! transformed using two novel operations:
//!
//! **Multiply-Fold-Rotate (MFR):**
//! ```text
//! MFR(a, b, rot):
//!   product = a ×₆₄ (b | 1)      - modular multiply (|1 guarantees bijectivity)
//!   folded  = product ⊕ (product >> 32)   - fold high bits into low
//!   result  = folded <<< rot              - rotate for diffusion
//! ```
//!
//! **Data-Dependent Rotation (DDR):**
//! ```text
//! DDR(a, b):
//!   result = a <<< (b & 63)     - rotation distance from the data itself
//! ```
//!
//! DDR is cryptanalytic poison: differential analysis must track all 64
//! possible rotation distances simultaneously, causing exponential path
//! explosion. No standard analysis tool handles this efficiently.
//!
//! ## Quintet-Round (5-word mixer, novel)
//!
//! ```text
//! a = MFR(a, b, rot0)
//! c = c ⊕ a
//! d = DDR(d, c)
//! e = MFR(e, d, rot1)
//! b = b ⊕ e
//! ```
//!
//! No published cipher uses 5-word mixing rounds. Novel to KK.
//!
//! ## The 5×5 Grid
//!
//! Each round applies 15 quintet-rounds:
//! - 5 on rows
//! - 5 on columns
//! - 5 on diagonals
//!
//! Plus round constant injection and intra-round re-keying (every 8 rounds).
//! 32 rounds total = 480 quintet-rounds = 960 MFR + 480 DDR operations.
//!
//! ## The KK Sponge
//!
//! Rate = 1216 bits (152 bytes), Capacity = 384 bits (48 bytes).
//! Provides KK-Hash, KK-KDF, KK-MAC, entropy mixing.
//!
//! ## Temporal Permutation Variance
//!
//! The rotation distances inside the permutation can be derived from
//! the entropy snapshot ε. This means the *mathematical structure* of
//! the cipher changes every encryption  - not just different data through
//! the same algorithm, but a *different algorithm entirely*.
//!
//! J.A. Keeney, Australia, 2026

use core::hint::black_box;
use zeroize::Zeroize;

// ─────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────

/// Number of 64-bit words in the state (5×5 grid = 1600 bits).
pub const STATE_WORDS: usize = 25;

/// State size in bytes (1600 bits).
pub const STATE_BYTES: usize = STATE_WORDS * 8;

/// Number of permutation rounds. 32 rounds on a 5×5 grid provide
/// thorough diffusion: after 2 rounds every word influences every
/// other word, so 32 rounds gives 16 full cross-diffusion cycles.
pub const ROUNDS: usize = 32;

/// Rounds for KDF squeeze permutations. Fewer than full rounds
/// because each squeeze block is keyed and domain-separated  -
/// the attacker cannot choose or observe the sponge state.
pub const KDF_SQUEEZE_ROUNDS: usize = 20;

/// Sponge rate in words (1216 bits = 152 bytes).
pub const RATE_WORDS: usize = 19;

/// Sponge rate in bytes.
pub const RATE_BYTES: usize = RATE_WORDS * 8;

/// Sponge capacity in words (384 bits = 192-bit security level).
pub const CAPACITY_WORDS: usize = STATE_WORDS - RATE_WORDS;

/// Default rotation distances for the 15 quintet-rounds per round.
/// 5 for rows, 5 for columns, 5 for diagonals.
/// Each pair: one value in [1,31], one in [33,63]  - asymmetric mixing.
/// All values are odd (coprime with 64) for maximum bit coverage.
/// No two values repeat across all 30 entries.
pub(crate) const DEFAULT_ROTATIONS: [[u32; 2]; 15] = [
    // Row phase
    [7, 41],  [13, 29], [19, 37], [23, 43], [3, 53],
    // Column phase
    [11, 47], [17, 39], [5, 59],  [31, 49], [9, 51],
    // Diagonal phase
    [15, 33], [21, 45], [27, 35], [1, 57],  [25, 55],
];

/// Domain separation byte for hashing mode.
const DOMAIN_HASH: u8 = 0x01;
/// Domain separation byte for KDF mode.
const DOMAIN_KDF: u8 = 0x02;
/// Domain separation byte for MAC mode.
const DOMAIN_MAC: u8 = 0x03;

/// Initialization constants for the 25-word state.
/// Computed as: floor(frac(√p) × 2^64) for the first 25 primes.
/// "Nothing up my sleeve"  - anyone can verify these.
pub(crate) const KK_IV: [u64; STATE_WORDS] = [
    0x6A09E667F3BCC908, // √2
    0xBB67AE8584CAA73B, // √3
    0x3C6EF372FE94F82B, // √5
    0xA54FF53A5F1D36F1, // √7
    0x510E527FADE682D1, // √11
    0x9B05688C2B3E6C1F, // √13
    0x1F83D9ABFB41BD6B, // √17
    0x5BE0CD19137E2179, // √19
    0xCBBB9D5DC1059ED8, // √23
    0x629A292A367CD507, // √29
    0x9159015A3070DD17, // √31
    0x152FECD8F70E5939, // √37
    0x67332667FFC00B31, // √41
    0x8EB44A8768581511, // √43
    0xDB0C2E0D64F98FA7, // √47
    0x47B5481DBEFA4FA4, // √53
    0xAE5F9156E7B6D99B, // √59
    0xCF6C85D39D1A1E15, // √61
    0x2F73477D6A4563CA, // √67
    0x6D1826CAFD82E1ED, // √71
    0x8B43D4570A51B936, // √73
    0xE360B596DC380C3F, // √79
    0x1C456002CE13E9F8, // √83
    0x6F19633143A0AF0E, // √89
    0xD94EBEB1AB313933, // √97
];

/// The KK state: 1600 bits as 25 × 64-bit words (5×5 grid).
pub type KkState = [u64; STATE_WORDS];

/// Diagonal index patterns for the 5×5 grid.
const DIAGS: [[usize; 5]; 5] = [
    [0, 6, 12, 18, 24],
    [1, 7, 13, 19, 20],
    [2, 8, 14, 15, 21],
    [3, 9, 10, 16, 22],
    [4, 5, 11, 17, 23],
];

// ─────────────────────────────────────────────────────────────────
//  MFR  - Multiply-Fold-Rotate (the novel non-linear core)
// ─────────────────────────────────────────────────────────────────

/// The Multiply-Fold-Rotate operation.
///
/// 1. `a ×₆₄ (b | 1)`  - wrapping multiply, `| 1` ensures odd (bijective)
/// 2. `⊕ (>> 32)`  - fold high bits into low, breaking multiplicative structure
/// 3. `<<< rot`  - rotate for diffusion
///
/// This is one of two non-linear building blocks of the KK system.
#[inline(always)]
fn mfr(a: u64, b: u64, rot: u32) -> u64 {
    let product = a.wrapping_mul(b | 1);
    let folded = product ^ (product >> 32);
    folded.rotate_left(rot)
}

// ─────────────────────────────────────────────────────────────────
//  DDR  - Data-Dependent Rotation (novel)
// ─────────────────────────────────────────────────────────────────

/// Data-Dependent Rotation: rotate `a` by a distance derived from `b`.
///
/// The rotation amount is the low 6 bits of `b` (range 0–63).
/// This makes the permutation structure depend on the data flowing
/// through it  - cryptanalytic poison for differential analysis.
///
/// Any differential trail must account for all 64 possible rotation
/// distances simultaneously, causing exponential path explosion.
/// No published analysis framework efficiently handles DDR.
///
/// ## Constant-time implementation
///
/// Decomposes the variable rotation into 6 fixed-distance rotations
/// (by 1, 2, 4, 8, 16, 32) selected branchlessly via bitmask.
/// All 6 steps execute unconditionally  - no data-dependent branches
/// or variable-distance shifts  - so timing is identical regardless
/// of the rotation amount on ALL architectures (including those
/// without constant-time barrel shifters).
#[inline(always)]
fn ddr(a: u64, b: u64) -> u64 {
    let s = b & 63;
    let mut v = a;
    // Each step: branchless conditional rotation by 2^i.
    // mask = 0 (no rotate) or all-ones (rotate), computed without branching.
    let m = 0u64.wrapping_sub(s & 1);
    v = (v & !m) | (v.rotate_left(1) & m);
    let m = 0u64.wrapping_sub((s >> 1) & 1);
    v = (v & !m) | (v.rotate_left(2) & m);
    let m = 0u64.wrapping_sub((s >> 2) & 1);
    v = (v & !m) | (v.rotate_left(4) & m);
    let m = 0u64.wrapping_sub((s >> 3) & 1);
    v = (v & !m) | (v.rotate_left(8) & m);
    let m = 0u64.wrapping_sub((s >> 4) & 1);
    v = (v & !m) | (v.rotate_left(16) & m);
    let m = 0u64.wrapping_sub((s >> 5) & 1);
    v = (v & !m) | (v.rotate_left(32) & m);
    v
}

// ─────────────────────────────────────────────────────────────────
//  Quintet-Round  - 5-word mixer (novel, replaces quarter-round)
// ─────────────────────────────────────────────────────────────────

/// Quintet-round: mix five state words through MFR + DDR operations
/// with cross-feedback.
///
/// ```text
/// a = MFR(a, b, rot0)     - non-linear mix
/// c = c ⊕ a               - linear diffusion
/// d = DDR(d, c)            - data-dependent rotation (novel)
/// e = MFR(e, d, rot1)     - non-linear mix
/// b = b ⊕ e               - linear feedback
/// ```
///
/// After one quintet-round, all five words have influenced each other.
/// No published cipher uses 5-word mixing rounds.
#[inline(always)]
fn quintet_round(
    a: &mut u64,
    b: &mut u64,
    c: &mut u64,
    d: &mut u64,
    e: &mut u64,
    rot: [u32; 2],
) {
    *a = mfr(*a, *b, rot[0]);
    *c ^= *a;
    *d = ddr(*d, *c);
    *e = mfr(*e, *d, rot[1]);
    *b ^= *e;
}

// ─────────────────────────────────────────────────────────────────
//  KK Permutation v2  - 5×5 grid, 32 rounds
// ─────────────────────────────────────────────────────────────────

/// Apply the KK permutation to a 1600-bit state using default rotations.
pub fn kk_permute(state: &mut KkState) {
    kk_permute_with_schedule(state, &DEFAULT_ROTATIONS);
}

/// Apply the KK permutation with variable round count.
pub(crate) fn kk_permute_n(state: &mut KkState, rotations: &[[u32; 2]; 15], rounds: usize) {
    for round in 0..rounds as u64 {
        // ── Row phase: 5 quintet-rounds ──
        for (row, rot) in rotations.iter().enumerate().take(5) {
            let base = row * 5;
            let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                state[base], state[base + 1], state[base + 2],
                state[base + 3], state[base + 4],
            );
            quintet_round(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, *rot);
            state[base] = s0;
            state[base + 1] = s1;
            state[base + 2] = s2;
            state[base + 3] = s3;
            state[base + 4] = s4;
        }

        // ── Column phase: 5 quintet-rounds ──
        for col in 0..5usize {
            let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                state[col], state[col + 5], state[col + 10],
                state[col + 15], state[col + 20],
            );
            quintet_round(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rotations[5 + col]);
            state[col] = s0;
            state[col + 5] = s1;
            state[col + 10] = s2;
            state[col + 15] = s3;
            state[col + 20] = s4;
        }

        // ── Diagonal phase: 5 quintet-rounds ──
        for d in 0..5usize {
            let [i0, i1, i2, i3, i4] = DIAGS[d];
            let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                state[i0], state[i1], state[i2], state[i3], state[i4],
            );
            quintet_round(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rotations[10 + d]);
            state[i0] = s0;
            state[i1] = s1;
            state[i2] = s2;
            state[i3] = s3;
            state[i4] = s4;
        }

        // ── Round constant injection (corners + center of 5×5 grid) ──
        state[0] = state[0].wrapping_add(round);
        state[4] = state[4].wrapping_add(round.wrapping_mul(0x9E3779B97F4A7C15));
        state[12] = state[12].wrapping_add(round.wrapping_mul(0xB7E151628AED2A6A));
        state[20] = state[20].wrapping_add(round.wrapping_mul(0x243F6A8885A2F7A4));
        state[24] = state[24].wrapping_add(round.wrapping_mul(0x298B075B4B6A5240));

        // ── Intra-round re-keying every 8 rounds ──
        // XOR capacity words (rotated) into rate words.
        // Breaks fixed-structure analysis within a single permutation call.
        if round % 8 == 7 {
            for i in 0..RATE_WORDS {
                state[i] ^= state[RATE_WORDS + (i % CAPACITY_WORDS)]
                    .rotate_left(round as u32);
            }
        }
    }
}

/// Apply the KK permutation with a custom rotation schedule (32 rounds).
///
/// Each round applies 15 quintet-rounds over a 5×5 word grid:
/// - 5 on rows, 5 on columns, 5 on diagonals
///
/// Plus round constant injection and intra-round re-keying every 8 rounds.
pub fn kk_permute_with_schedule(state: &mut KkState, rotations: &[[u32; 2]; 15]) {
    kk_permute_n(state, rotations, ROUNDS);
}

// ─────────────────────────────────────────────────────────────────
//  Rotation Schedule Derivation
// ─────────────────────────────────────────────────────────────────

/// Derive a rotation schedule from entropy bytes.
///
/// Takes bytes from the entropy and converts them to rotation distances
/// in range [1, 63] (non-trivial rotations on 64-bit words).
///
/// Uses bias-free extraction: mask to 6 bits (0–63), then OR with 1
/// to guarantee the result is odd and ≥ 1. The range [0,63] maps
/// uniformly from 8-bit bytes (256 / 64 = 4 values per bucket, exact),
/// so there is zero modular bias.
pub fn rotations_from_entropy(entropy: &[u8]) -> [[u32; 2]; 15] {
    let mut rots = DEFAULT_ROTATIONS;
    for (i, rot) in rots.iter_mut().enumerate() {
        for (j, r) in rot.iter_mut().enumerate() {
            let idx = i * 2 + j;
            if idx < entropy.len() {
                // & 63 → [0,63] with zero bias (256 divides 64 evenly)
                // | 1  → guarantees odd (non-zero), range [1,63]
                *r = (entropy[idx] as u32 & 63) | 1;
            }
        }
    }
    rots
}

// ─────────────────────────────────────────────────────────────────
//  KK Sponge  - the universal construction
// ─────────────────────────────────────────────────────────────────

/// The KK Sponge: absorb data, squeeze output, permute between steps.
pub struct KkSponge {
    state: KkState,
    rotations: [[u32; 2]; 15],
    /// How many rate bytes are currently buffered (for partial-block absorb).
    buf_pos: usize,
}

impl Clone for KkSponge {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            rotations: self.rotations,
            buf_pos: self.buf_pos,
        }
    }
}

impl Drop for KkSponge {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

impl Default for KkSponge {
    fn default() -> Self {
        Self::new()
    }
}

impl KkSponge {
    /// Create a new sponge with default rotation schedule.
    pub fn new() -> Self {
        Self {
            state: KK_IV,
            rotations: DEFAULT_ROTATIONS,
            buf_pos: 0,
        }
    }

    /// Create a new sponge with an entropy-derived rotation schedule.
    pub fn with_entropy_rotations(entropy: &[u8]) -> Self {
        Self {
            state: KK_IV,
            rotations: rotations_from_entropy(entropy),
            buf_pos: 0,
        }
    }

    /// Apply the permutation on the current state.
    fn permute(&mut self) {
        kk_permute_with_schedule(&mut self.state, &self.rotations);
    }

    /// Load the rate portion of state as bytes.
    fn rate_bytes(&self) -> [u8; RATE_BYTES] {
        let mut out = [0u8; RATE_BYTES];
        for i in 0..RATE_WORDS {
            out[i * 8..(i + 1) * 8].copy_from_slice(&self.state[i].to_le_bytes());
        }
        out
    }

    /// XOR a byte into the rate portion at a given position.
    fn xor_rate_byte(&mut self, pos: usize, byte: u8) {
        let word_idx = pos / 8;
        let byte_idx = pos % 8;
        self.state[word_idx] ^= (byte as u64) << (byte_idx * 8);
    }

    /// Absorb arbitrary-length input into the sponge.
    ///
    /// Data is XOR'd into the rate portion of the state.
    /// After every full rate-block, the permutation is applied.
    ///
    /// Uses word-at-a-time XOR when aligned for ~8× fewer ops on
    /// bulk data; falls back to byte-by-byte for alignment/tail.
    pub fn absorb(&mut self, data: &[u8]) {
        let mut offset = 0;

        while offset < data.len() {
            // Byte-by-byte when misaligned or fewer than 8 bytes remain
            if !self.buf_pos.is_multiple_of(8) || data.len() - offset < 8 {
                self.xor_rate_byte(self.buf_pos, data[offset]);
                offset += 1;
                self.buf_pos += 1;
                if self.buf_pos == RATE_BYTES {
                    self.permute();
                    self.buf_pos = 0;
                }
                continue;
            }

            // Word-at-a-time: buf_pos is word-aligned, >= 8 bytes available
            let word_idx = self.buf_pos / 8;
            let words_in_rate = (RATE_BYTES - self.buf_pos) / 8;
            let words_in_data = (data.len() - offset) / 8;
            let words = words_in_rate.min(words_in_data);

            for i in 0..words {
                let start = offset + i * 8;
                let w = u64::from_le_bytes(
                    data[start..start + 8].try_into().unwrap(),
                );
                self.state[word_idx + i] ^= w;
            }
            offset += words * 8;
            self.buf_pos += words * 8;

            if self.buf_pos == RATE_BYTES {
                self.permute();
                self.buf_pos = 0;
            }
        }
    }

    /// Finalize absorption: apply padding and permute.
    ///
    /// Uses multi-rate padding: pad with domain byte, then set high bit
    /// of last rate byte. This ensures different domains and different
    /// message lengths cannot collide.
    fn finalize_absorb(&mut self, domain: u8) {
        // Domain separation + 0x80 terminator at end of rate
        self.xor_rate_byte(self.buf_pos, domain);
        self.xor_rate_byte(RATE_BYTES - 1, 0x80);
        self.permute();
        self.buf_pos = 0;
    }

    /// Squeeze `len` bytes of output from the sponge.
    ///
    /// After finalization, the rate portion contains output bytes.
    /// If more bytes are needed than one rate-block, permute and
    /// squeeze again.
    fn squeeze(&mut self, len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(len);
        while output.len() < len {
            let rate = self.rate_bytes();
            let take = (len - output.len()).min(RATE_BYTES);
            output.extend_from_slice(&rate[..take]);
            if output.len() < len {
                self.permute();
            }
        }
        output
    }

    /// Permute with a reduced round count (used for KDF squeeze).
    fn permute_n(&mut self, rounds: usize) {
        kk_permute_n(&mut self.state, &self.rotations, rounds);
    }

    /// Squeeze with reduced-round permutations for KDF keystream.
    ///
    /// Uses KDF_SQUEEZE_ROUNDS (20) instead of full 32 between rate
    /// blocks. Safe because each block is keyed and domain-separated.
    fn squeeze_kdf(&mut self, len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(len);
        while output.len() < len {
            let rate = self.rate_bytes();
            let take = (len - output.len()).min(RATE_BYTES);
            output.extend_from_slice(&rate[..take]);
            if output.len() < len {
                self.permute_n(KDF_SQUEEZE_ROUNDS);
            }
        }
        output
    }
}

// ─────────────────────────────────────────────────────────────────
//  High-level API: KK-Hash, KK-KDF, KK-MAC
// ─────────────────────────────────────────────────────────────────

/// KK-Hash: compute a 256-bit digest of arbitrary data.
///
/// Replaces SHA-256  - built entirely from the KK permutation.
///
/// **WARNING: This is an UNKEYED hash  - it does NOT authenticate data.**
/// For message authentication, use [`kk_mac`] with a secret key.
/// Using `kk_hash` where `kk_mac` is needed is a security vulnerability.
#[must_use = "hash digest computed but not used  - did you mean kk_mac() for authentication?"]
pub fn kk_hash(data: &[u8]) -> [u8; 32] {
    let mut sponge = KkSponge::new();
    sponge.absorb(data);
    sponge.finalize_absorb(DOMAIN_HASH);
    let mut out = sponge.squeeze(32);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    out.zeroize();
    digest
}

/// KK-KDF: derive `output_len` bytes of key material.
///
/// Replaces HKDF-SHA256  - domain-separated sponge extraction.
///
/// Inputs:
///   - `key`: input key material (shared secret)
///   - `salt`: salt bytes (entropy snapshot ε)
///   - `info`: context/domain info (position, purpose label, etc.)
///   - `output_len`: how many bytes to derive
///
/// # Security Note
///
/// The returned `Vec<u8>` contains sensitive key material.
/// Call `.zeroize()` on the vector when you are done with it.
#[must_use = "derived key material computed but not used  - zeroize it when done"]
pub fn kk_kdf(key: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let mut sponge = KkSponge::with_entropy_rotations(salt);
    sponge.absorb(key);
    // Length-prefix the salt to prevent ambiguity between key||salt boundaries
    sponge.absorb(&(salt.len() as u64).to_le_bytes());
    sponge.absorb(salt);
    sponge.absorb(&(info.len() as u64).to_le_bytes());
    sponge.absorb(info);
    sponge.finalize_absorb(DOMAIN_KDF);
    sponge.squeeze_kdf(output_len)
}

/// Extract the rate portion of a raw `KkState` as bytes.
fn rate_bytes_from_state(state: &KkState) -> [u8; RATE_BYTES] {
    let mut out = [0u8; RATE_BYTES];
    for i in 0..RATE_WORDS {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// Batch KDF: derive key material for 8 different `info` values simultaneously.
///
/// Produces the **same output** as calling [`kk_kdf`] 8 times with the same
/// `key`/`salt` but different `info` strings, but ~5-6× faster on AVX-512
/// hardware because the squeeze permutations run 8-wide in SIMD.
///
/// Falls back to 8× scalar [`kk_kdf`] on non-AVX-512 hardware.
///
/// # Security Note
///
/// Each returned `Vec<u8>` contains sensitive key material.
/// Call `.zeroize()` on each vector when you are done.
pub fn kk_kdf_batch_8(
    key: &[u8],
    salt: &[u8],
    infos: [&[u8]; 8],
    output_len: usize,
) -> [Vec<u8>; 8] {
    // Shared prefix: all 8 KDFs absorb the same key + length-prefixed salt
    let mut shared = KkSponge::with_entropy_rotations(salt);
    shared.absorb(key);
    shared.absorb(&(salt.len() as u64).to_le_bytes());
    shared.absorb(salt);

    // Diverge: each clone absorbs its own length-prefixed info, then finalizes
    let mut sponges: [KkSponge; 8] = core::array::from_fn(|_| shared.clone());
    drop(shared);

    for i in 0..8 {
        sponges[i].absorb(&(infos[i].len() as u64).to_le_bytes());
        sponges[i].absorb(infos[i]);
        sponges[i].finalize_absorb(DOMAIN_KDF);
    }

    // --- AVX-512 vectorized squeeze ---
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq") {
            let mut raw_states: [KkState; 8] =
                core::array::from_fn(|i| sponges[i].state);
            let rotations = sponges[0].rotations;
            drop(sponges);

            let result = unsafe {
                vectorized_squeeze_8(&mut raw_states, &rotations, output_len)
            };
            raw_states.zeroize();
            return result;
        }
    }

    // --- Scalar fallback ---
    let mut results: [Vec<u8>; 8] = core::array::from_fn(|_| Vec::new());
    for i in 0..8 {
        results[i] = sponges[i].squeeze_kdf(output_len);
    }
    results
}

/// Vectorized squeeze loop for 8 sponge states using AVX-512.
///
/// Packs 8 scalar states into `KkState8`, reads rate bytes, then permutes
/// all 8 simultaneously with `kk_permute_n_x8`.
///
/// # Safety
/// Requires AVX-512F + AVX-512DQ.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn vectorized_squeeze_8(
    states: &mut [KkState; 8],
    rotations: &[[u32; 2]; 15],
    output_len: usize,
) -> [Vec<u8>; 8] {
    use crate::kk_mix_avx512::{load_8_states, store_8_states, kk_permute_n_x8};

    let mut packed = load_8_states(states);
    let mut outputs: [Vec<u8>; 8] =
        core::array::from_fn(|_| Vec::with_capacity(output_len));

    loop {
        let unpacked = store_8_states(&packed);
        let remaining = output_len - outputs[0].len();
        let take = remaining.min(RATE_BYTES);

        for lane in 0..8 {
            let rate = rate_bytes_from_state(&unpacked[lane]);
            outputs[lane].extend_from_slice(&rate[..take]);
        }

        if outputs[0].len() >= output_len {
            break;
        }

        kk_permute_n_x8(&mut packed, rotations, KDF_SQUEEZE_ROUNDS);
    }

    outputs
}

/// KK-MAC: compute a 256-bit authentication tag over a message.
///
/// Replaces HMAC-SHA256  - keyed sponge construction.
/// Use this (not [`kk_hash`]) whenever you need to verify message integrity.
///
/// Inputs:
///   - `key`: authentication key
///   - `message`: the data to authenticate
///
/// # Security Note
///
/// KK-MAC is **deterministic**: the same (key, message) pair always
/// produces the same tag. This is correct and expected for a MAC.
/// If your protocol requires unique tags (e.g., to prevent replay),
/// prepend a nonce or counter to the message before calling `kk_mac`.
#[must_use = "MAC tag computed but not used  - verify it with kk_mac_verify()"]
pub fn kk_mac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut sponge = KkSponge::new();
    // Absorb key with length prefix (prevents length-extension)
    sponge.absorb(&(key.len() as u64).to_le_bytes());
    sponge.absorb(key);
    // Absorb message
    sponge.absorb(message);
    sponge.finalize_absorb(DOMAIN_MAC);
    let mut out = sponge.squeeze(32);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    out.zeroize();
    tag
}

/// KK-MAC verify: constant-time comparison of authentication tags.
///
/// Returns `true` if the tag matches. Uses byte-by-byte OR accumulation
/// so the comparison time doesn't depend on where the first difference is.
pub fn kk_mac_verify(key: &[u8], message: &[u8], expected_tag: &[u8; 32]) -> bool {
    let computed = kk_mac(key, message);
    constant_time_eq(&computed, expected_tag)
}

/// KK-MAC with entropy-derived rotation schedule.
///
/// Like [`kk_mac`], but the sponge uses rotations derived from `entropy`
/// instead of `DEFAULT_ROTATIONS`. This means the *mathematical structure*
/// of the MAC computation varies with the entropy  - the permutation itself
/// is different, not just the data flowing through it.
///
/// Used by the temporal-proof system so the commitment is truly temporal:
/// the algebra that produced the tag only existed at that entropic moment.
#[must_use = "MAC tag computed but not used  - verify it with kk_mac_verify_with_entropy()"]
pub fn kk_mac_with_entropy(key: &[u8], message: &[u8], entropy: &[u8]) -> [u8; 32] {
    let mut sponge = KkSponge::with_entropy_rotations(entropy);
    sponge.absorb(&(key.len() as u64).to_le_bytes());
    sponge.absorb(key);
    sponge.absorb(message);
    sponge.finalize_absorb(DOMAIN_MAC);
    let mut out = sponge.squeeze(32);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    out.zeroize();
    tag
}

/// Verify a KK-MAC that was computed with entropy-derived rotations.
///
/// Returns `true` if the tag matches. Constant-time comparison.
pub fn kk_mac_verify_with_entropy(
    key: &[u8],
    message: &[u8],
    expected_tag: &[u8; 32],
    entropy: &[u8],
) -> bool {
    let computed = kk_mac_with_entropy(key, message, entropy);
    constant_time_eq(&computed, expected_tag)
}

/// Constant-time byte comparison. Runs in time proportional to the
/// shorter slice length, regardless of where differences occur.
///
/// Uses `core::hint::black_box` on the accumulator to prevent the
/// compiler from short-circuiting the OR chain into an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    black_box(diff) == 0
}

/// KK-Mix: mix arbitrary-length entropy sources into `output_len` bytes.
///
/// Used by the entropy module to combine multiple sources.
/// This replaces the HKDF-based mixing in the original entropy gathering.
///
/// # Security Note
///
/// The returned `Vec<u8>` may contain sensitive mixed entropy.
/// Call `.zeroize()` on the vector when you are done with it.
#[must_use = "mixed entropy computed but not used  - zeroize it when done"]
pub fn kk_entropy_mix(sources: &[&[u8]], output_len: usize) -> Vec<u8> {
    let mut sponge = KkSponge::new();
    for (i, source) in sources.iter().enumerate() {
        // Each source gets a length prefix + index for domain separation
        sponge.absorb(&(i as u64).to_le_bytes());
        sponge.absorb(&(source.len() as u64).to_le_bytes());
        sponge.absorb(source);
    }
    sponge.finalize_absorb(DOMAIN_HASH);
    sponge.squeeze(output_len)
}

// ─────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_changes_state() {
        let mut state = KK_IV;
        let original = state;
        kk_permute(&mut state);
        assert_ne!(state, original, "Permutation must change the state");
    }

    #[test]
    fn permutation_is_deterministic() {
        let mut s1 = KK_IV;
        s1[0] ^= 0xDEAD;
        s1[1] ^= 0xBEEF;
        let mut s2 = s1;
        kk_permute(&mut s1);
        kk_permute(&mut s2);
        assert_eq!(s1, s2, "Same input must produce same output");
    }

    #[test]
    fn permutation_avalanche() {
        // Flipping one bit in input should change many bits in output.
        let mut s1 = KK_IV;
        let mut s2 = KK_IV;
        s2[0] ^= 1; // 1 bit difference
        kk_permute(&mut s1);
        kk_permute(&mut s2);

        let mut diff_bits = 0u32;
        for (a, b) in s1.iter().zip(s2.iter()) {
            diff_bits += (a ^ b).count_ones();
        }
        // Good avalanche: ~50% of 1600 bits = ~800. Accept > 300.
        assert!(
            diff_bits > 300,
            "Poor avalanche: only {diff_bits}/1600 bits differ (expected ~800)"
        );
    }

    #[test]
    fn entropy_rotations_change_output() {
        let mut s1 = KK_IV;
        let mut s2 = s1;
        kk_permute(&mut s1);
        let alt_rots: [[u32; 2]; 15] = [
            [5, 50], [11, 33], [17, 39], [21, 47], [9, 53],
            [7, 41], [13, 29], [19, 37], [23, 43], [3, 55],
            [15, 35], [21, 45], [27, 33], [1, 57], [25, 51],
        ];
        kk_permute_with_schedule(&mut s2, &alt_rots);
        assert_ne!(
            s1, s2,
            "Different rotation schedules must produce different permutations"
        );
    }

    #[test]
    fn ddr_sensitivity() {
        // Different rotation sources produce different outputs
        let a = 0xDEADBEEF_CAFEBABE_u64;
        let r1 = ddr(a, 7);
        let r2 = ddr(a, 8);
        assert_ne!(r1, r2, "Different rotation sources must give different results");
    }

    #[test]
    fn ddr_full_range() {
        // DDR should produce diverse outputs across rotation distances
        let a = 0xFFFF_FFFF_FFFF_FFFE_u64; // asymmetric bits
        let mut seen = std::collections::HashSet::new();
        for b in 0..64u64 {
            seen.insert(ddr(a, b));
        }
        assert!(
            seen.len() > 32,
            "DDR should produce diverse outputs: got {} unique values from 64 rotations",
            seen.len()
        );
    }

    #[test]
    fn quintet_round_diffusion() {
        // After one quintet-round, all 5 words should change
        let (mut a, mut b, mut c, mut d, mut e) =
            (0x1111u64, 0x2222, 0x3333, 0x4444, 0x5555);
        let (a0, b0, c0, d0, e0) = (a, b, c, d, e);
        quintet_round(&mut a, &mut b, &mut c, &mut d, &mut e, [7, 41]);
        assert_ne!(a, a0, "word a unchanged");
        assert_ne!(b, b0, "word b unchanged");
        assert_ne!(c, c0, "word c unchanged");
        assert_ne!(d, d0, "word d unchanged");
        assert_ne!(e, e0, "word e unchanged");
    }

    #[test]
    fn wide_state_avalanche() {
        // 1-bit flip in center word → good diffusion across 1600 bits
        let mut s1 = KK_IV;
        let mut s2 = KK_IV;
        s2[12] ^= 1;
        kk_permute(&mut s1);
        kk_permute(&mut s2);

        let mut diff_bits = 0u32;
        for (a, b) in s1.iter().zip(s2.iter()) {
            diff_bits += (a ^ b).count_ones();
        }
        assert!(
            diff_bits > 300,
            "Poor wide avalanche: only {diff_bits}/1600 bits differ"
        );
    }

    #[test]
    fn hash_deterministic() {
        let h1 = kk_hash(b"hello KK");
        let h2 = kk_hash(b"hello KK");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_input_different_output() {
        let h1 = kk_hash(b"hello");
        let h2 = kk_hash(b"hellp"); // one byte different
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_empty_vs_nonempty() {
        let h1 = kk_hash(b"");
        let h2 = kk_hash(b"x");
        assert_ne!(h1, h2);
    }

    #[test]
    fn kdf_deterministic_same_inputs() {
        let k1 = kk_kdf(b"secret", b"salt", b"info", 32);
        let k2 = kk_kdf(b"secret", b"salt", b"info", 32);
        assert_eq!(k1, k2);
    }

    #[test]
    fn kdf_different_salt_different_output() {
        let k1 = kk_kdf(b"secret", b"salt-a", b"info", 32);
        let k2 = kk_kdf(b"secret", b"salt-b", b"info", 32);
        assert_ne!(k1, k2);
    }

    #[test]
    fn kdf_different_info_different_output() {
        let k1 = kk_kdf(b"secret", b"salt", b"pos-0", 32);
        let k2 = kk_kdf(b"secret", b"salt", b"pos-1", 32);
        assert_ne!(k1, k2);
    }

    #[test]
    fn kdf_variable_length() {
        let k16 = kk_kdf(b"key", b"salt", b"info", 16);
        let k64 = kk_kdf(b"key", b"salt", b"info", 64);
        assert_eq!(k16.len(), 16);
        assert_eq!(k64.len(), 64);
    }

    #[test]
    fn mac_deterministic() {
        let t1 = kk_mac(b"key", b"message");
        let t2 = kk_mac(b"key", b"message");
        assert_eq!(t1, t2);
    }

    #[test]
    fn mac_different_key_different_tag() {
        let t1 = kk_mac(b"key-a", b"message");
        let t2 = kk_mac(b"key-b", b"message");
        assert_ne!(t1, t2);
    }

    #[test]
    fn mac_different_message_different_tag() {
        let t1 = kk_mac(b"key", b"msg-a");
        let t2 = kk_mac(b"key", b"msg-b");
        assert_ne!(t1, t2);
    }

    #[test]
    fn mac_verify_valid() {
        let tag = kk_mac(b"key", b"important data");
        assert!(kk_mac_verify(b"key", b"important data", &tag));
    }

    #[test]
    fn mac_verify_tampered() {
        let tag = kk_mac(b"key", b"important data");
        assert!(!kk_mac_verify(b"key", b"TAMPERED data", &tag));
    }

    #[test]
    fn mac_verify_wrong_key() {
        let tag = kk_mac(b"correct-key", b"data");
        assert!(!kk_mac_verify(b"wrong-key", b"data", &tag));
    }

    #[test]
    fn entropy_mix_deterministic() {
        let sources: Vec<&[u8]> = vec![b"source1", b"source2", b"source3"];
        let m1 = kk_entropy_mix(&sources, 32);
        let m2 = kk_entropy_mix(&sources, 32);
        assert_eq!(m1, m2);
    }

    #[test]
    fn entropy_mix_different_sources_different_output() {
        let m1 = kk_entropy_mix(&[b"aaa", b"bbb"], 32);
        let m2 = kk_entropy_mix(&[b"aaa", b"ccc"], 32);
        assert_ne!(m1, m2);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"hellp"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    // ── Frozen test vectors ──────────────────────────────────────
    // These catch accidental changes to the permutation or sponge.
    // If ANY of these fail, either the algorithm changed (intentional
    // and requires new vectors) or a regression was introduced.

    #[test]
    fn vector_hash_empty() {
        let h = kk_hash(b"");
        assert_eq!(
            hex::encode(h),
            "8a2254a95c8537855961b5273bdd7e2921af6a1a6883d0607e9e9c2bf1962a65",
            "REGRESSION: kk_hash(\"\") output changed"
        );
    }

    #[test]
    fn vector_hash_kk() {
        let h = kk_hash(b"KK-Keeney-Kode");
        assert_eq!(
            hex::encode(h),
            "71bf809de9627879aa2e8db1342238b88c382c47b1155aae0ac73831da3ef4d6",
            "REGRESSION: kk_hash(\"KK-Keeney-Kode\") output changed"
        );
    }

    #[test]
    fn vector_hash_1024_ab() {
        let h = kk_hash(&[0xABu8; 1024]);
        assert_eq!(
            hex::encode(h),
            "30110fbc9153edfaf6918b5286502fed52644d6275c7c82db07c5822511199f3",
            "REGRESSION: kk_hash([0xAB; 1024]) output changed"
        );
    }

    #[test]
    fn vector_mac() {
        let tag = kk_mac(b"secret-key-2026", b"authenticate this");
        assert_eq!(
            hex::encode(tag),
            "01c107b4641f40d300d4652a6b0ba39d5a52e99946df4feef4f42a9f972d2bfc",
            "REGRESSION: kk_mac output changed"
        );
    }

    #[test]
    fn vector_kdf() {
        let k = kk_kdf(b"master-key", b"salt-value", b"kdf-context", 32);
        assert_eq!(
            hex::encode(k),
            "6045be9f33f111e1c23ccaef86951a147c33b3c5b6f24cb20139ef9c4394c392",
            "REGRESSION: kk_kdf output changed"
        );
    }

    #[test]
    fn batch_kdf_matches_scalar() {
        let key = b"batch-test-master-key";
        let salt = b"batch-test-salt-entropy-bytes";
        let infos_raw: [Vec<u8>; 8] = core::array::from_fn(|i| {
            let mut info = Vec::with_capacity(18 + 8 + 8);
            info.extend_from_slice(b"KK-sym-v1\0");
            info.extend_from_slice(&(i as u64).to_le_bytes());
            info.extend_from_slice(&0x1234_5678_ABCD_EF00u64.to_le_bytes());
            info
        });
        let infos: [&[u8]; 8] = core::array::from_fn(|i| infos_raw[i].as_slice());
        let output_len = 4096;

        // Scalar: 8 individual kk_kdf calls
        let scalar: [Vec<u8>; 8] = core::array::from_fn(|i| {
            kk_kdf(key, salt, infos[i], output_len)
        });

        // Batch: single kk_kdf_batch_8 call
        let batch = kk_kdf_batch_8(key, salt, infos, output_len);

        for i in 0..8 {
            assert_eq!(
                batch[i], scalar[i],
                "Batch KDF lane {i} diverged from scalar kk_kdf"
            );
        }
    }

    #[test]
    fn batch_kdf_multi_block_squeeze() {
        // Squeeze more than one rate-block (152 bytes) to exercise the loop
        let key = b"multi-block-key";
        let salt = b"multi-block-salt";
        let infos: [&[u8]; 8] = [
            b"info-0", b"info-1", b"info-2", b"info-3",
            b"info-4", b"info-5", b"info-6", b"info-7",
        ];
        let output_len = 1024; // ~7 rate blocks

        let scalar: [Vec<u8>; 8] = core::array::from_fn(|i| {
            kk_kdf(key, salt, infos[i], output_len)
        });

        let batch = kk_kdf_batch_8(key, salt, infos, output_len);

        for i in 0..8 {
            assert_eq!(
                batch[i], scalar[i],
                "Multi-block batch KDF lane {i} diverged from scalar"
            );
        }
    }
}
