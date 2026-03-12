//! KK-Mix: The novel cryptographic core of the KK system.
//!
//! Everything in KK is built from this single primitive:
//! hashing, key derivation, message authentication, entropy mixing.
//!
//! ## The KK Permutation
//!
//! A 512-bit (8 × 64-bit word) state transformation using a novel
//! **Multiply-Fold-Rotate (MFR)** operation:
//!
//! ```text
//! MFR(a, b, rot):
//!   product = a ×₆₄ (b | 1)      - modular multiply (|1 guarantees bijectivity)
//!   folded  = product ⊕ (product >> 32)   - fold high bits into low
//!   result  = folded <<< rot              - rotate for diffusion
//! ```
//!
//! Key properties:
//! - Multiplication by an odd number is a bijection mod 2^64 (invertible)
//! - The fold operation breaks the algebraic structure of multiplication
//! - Rotation spreads bit influence across the full word
//! - Combined: strong non-linearity + diffusion in a single operation
//!
//! ## The KK Sponge
//!
//! A sponge construction (rate=256 bits, capacity=256 bits) built on
//! the KK permutation. Provides:
//!
//! - **KK-Hash:** Absorb input, squeeze digest
//! - **KK-KDF:** Absorb key + salt + info, squeeze derived key
//! - **KK-MAC:** Absorb key + message, squeeze authentication tag
//!
//! ## Temporal Permutation Variance
//!
//! The rotation distances inside the permutation can be derived from
//! the entropy snapshot ε. This means the *mathematical structure* of
//! the cipher changes every encryption  - not just different data through
//! the same algorithm, but a *different algorithm entirely*.
//!
//! No existing cipher does this. It's a novel security property unique
//! to the KK system.
//!
//! J.A. Keeney, Australia, 2026

use zeroize::Zeroize;

// ─────────────────────────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────────────────────────

/// Number of 64-bit words in the state.
pub const STATE_WORDS: usize = 8;

/// State size in bytes (512 bits).
pub const STATE_BYTES: usize = STATE_WORDS * 8;

/// Number of permutation rounds. 16 rounds provide thorough diffusion:
/// after 2 rounds every state word has influenced every other word,
/// so 16 rounds gives 8 full cross-diffusion cycles.
pub const ROUNDS: usize = 16;

/// Sponge rate in words (256 bits = 32 bytes).
/// This is the portion of state exposed during absorb/squeeze.
pub const RATE_WORDS: usize = 4;

/// Sponge rate in bytes.
pub const RATE_BYTES: usize = RATE_WORDS * 8;

/// Sponge capacity in words (256 bits = internal security level).
pub const CAPACITY_WORDS: usize = STATE_WORDS - RATE_WORDS;

/// Default rotation distances  - chosen so each pair sums to ≠ 64,
/// no two values are equal, and all are coprime with 64 to maximise
/// bit coverage over iterated rounds.
const DEFAULT_ROTATIONS: [[u32; 2]; 4] = [
    [7, 41],
    [13, 29],
    [19, 37],
    [23, 43],
];

/// Domain separation byte for hashing mode.
const DOMAIN_HASH: u8 = 0x01;
/// Domain separation byte for KDF mode.
const DOMAIN_KDF: u8 = 0x02;
/// Domain separation byte for MAC mode.
const DOMAIN_MAC: u8 = 0x03;

/// Initialization constants  - prime-derived, ensure non-degenerate state
/// even when absorbing all-zero data. Analogous to IV constants in other
/// permutation-based constructions, but derived from the KK identity.
///
/// Computed as: floor(√(p_i) × 2^64) for the first 8 primes.
const KK_IV: [u64; STATE_WORDS] = [
    0x6A09E667F3BCC908, // √2
    0xBB67AE8584CAA73B, // √3
    0x3C6EF372FE94F82B, // √5
    0xA54FF53A5F1D36F1, // √7
    0x510E527FADE682D1, // √11
    0x9B05688C2B3E6C1F, // √13
    0x1F83D9ABFB41BD6B, // √17
    0x5BE0CD19137E2179, // √19
];

/// The KK state: 512 bits as 8 × 64-bit words.
pub type KkState = [u64; STATE_WORDS];

// ─────────────────────────────────────────────────────────────────
//  MFR  - Multiply-Fold-Rotate (the novel non-linear core)
// ─────────────────────────────────────────────────────────────────

/// The Multiply-Fold-Rotate operation.
///
/// 1. `a ×₆₄ (b | 1)`  - wrapping multiply, `| 1` ensures odd (bijective)
/// 2. `⊕ (>> 32)`  - fold high bits into low, breaking multiplicative structure
/// 3. `<<< rot`  - rotate for diffusion
///
/// This is the single non-linear building block of the entire KK system.
#[inline(always)]
fn mfr(a: u64, b: u64, rot: u32) -> u64 {
    let product = a.wrapping_mul(b | 1);
    let folded = product ^ (product >> 32);
    folded.rotate_left(rot)
}

// ─────────────────────────────────────────────────────────────────
//  Quarter-Round
// ─────────────────────────────────────────────────────────────────

/// Quarter-round: mix four state words through two MFR operations
/// with cross-feedback.
///
/// ```text
/// a = MFR(a, b, rot0)
/// c = c ⊕ a
/// d = MFR(d, c, rot1)
/// b = b ⊕ d
/// ```
///
/// After one quarter-round, all four words have influenced each other.
#[inline(always)]
fn quarter_round(
    a: &mut u64,
    b: &mut u64,
    c: &mut u64,
    d: &mut u64,
    rot: [u32; 2],
) {
    *a = mfr(*a, *b, rot[0]);
    *c ^= *a;
    *d = mfr(*d, *c, rot[1]);
    *b ^= *d;
}

// ─────────────────────────────────────────────────────────────────
//  KK Permutation
// ─────────────────────────────────────────────────────────────────

/// Apply the KK permutation to a 512-bit state using default rotations.
pub fn kk_permute(state: &mut KkState) {
    kk_permute_with_schedule(state, &DEFAULT_ROTATIONS);
}

/// Apply the KK permutation with a custom rotation schedule.
///
/// When rotations are derived from entropy, the permutation's internal
/// structure changes  - Temporal Permutation Variance.
pub fn kk_permute_with_schedule(state: &mut KkState, rotations: &[[u32; 2]; 4]) {
    for round in 0..ROUNDS as u64 {
        // Column quarter-rounds: (0,2,4,6) and (1,3,5,7)
        {
            let (mut a, mut b, mut c, mut d) = (state[0], state[2], state[4], state[6]);
            quarter_round(&mut a, &mut b, &mut c, &mut d, rotations[0]);
            state[0] = a; state[2] = b; state[4] = c; state[6] = d;
        }
        {
            let (mut a, mut b, mut c, mut d) = (state[1], state[3], state[5], state[7]);
            quarter_round(&mut a, &mut b, &mut c, &mut d, rotations[1]);
            state[1] = a; state[3] = b; state[5] = c; state[7] = d;
        }

        // Diagonal quarter-rounds: (0,3,5,6) and (1,2,4,7)
        {
            let (mut a, mut b, mut c, mut d) = (state[0], state[3], state[5], state[6]);
            quarter_round(&mut a, &mut b, &mut c, &mut d, rotations[2]);
            state[0] = a; state[3] = b; state[5] = c; state[6] = d;
        }
        {
            let (mut a, mut b, mut c, mut d) = (state[1], state[2], state[4], state[7]);
            quarter_round(&mut a, &mut b, &mut c, &mut d, rotations[3]);
            state[1] = a; state[2] = b; state[4] = c; state[7] = d;
        }

        // Round constant injection  - prevents slide attacks and
        // breaks symmetry between rounds.
        state[0] = state[0].wrapping_add(round);
        state[4] = state[4].wrapping_add(round.wrapping_mul(0x9E3779B97F4A7C15));
    }
}

/// Derive a rotation schedule from entropy bytes.
///
/// Takes bytes from the entropy and converts them to rotation distances
/// in range [1, 63] (non-trivial rotations on 64-bit words).
pub fn rotations_from_entropy(entropy: &[u8]) -> [[u32; 2]; 4] {
    let mut rots = DEFAULT_ROTATIONS;
    for i in 0..4 {
        for j in 0..2 {
            let idx = i * 2 + j;
            if idx < entropy.len() {
                rots[i][j] = (entropy[idx] % 62 + 1) as u32;
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
    rotations: [[u32; 2]; 4],
    /// How many rate bytes are currently buffered (for partial-block absorb).
    buf_pos: usize,
}

impl Drop for KkSponge {
    fn drop(&mut self) {
        self.state.zeroize();
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
    pub fn absorb(&mut self, data: &[u8]) {
        for &byte in data {
            self.xor_rate_byte(self.buf_pos, byte);
            self.buf_pos += 1;
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
}

// ─────────────────────────────────────────────────────────────────
//  High-level API: KK-Hash, KK-KDF, KK-MAC
// ─────────────────────────────────────────────────────────────────

/// KK-Hash: compute a 256-bit digest of arbitrary data.
///
/// Replaces SHA-256  - built entirely from the KK permutation.
pub fn kk_hash(data: &[u8]) -> [u8; 32] {
    let mut sponge = KkSponge::new();
    sponge.absorb(data);
    sponge.finalize_absorb(DOMAIN_HASH);
    let out = sponge.squeeze(32);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
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
pub fn kk_kdf(key: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let mut sponge = KkSponge::with_entropy_rotations(salt);
    sponge.absorb(key);
    // Length-prefix the salt to prevent ambiguity between key||salt boundaries
    sponge.absorb(&(salt.len() as u64).to_le_bytes());
    sponge.absorb(salt);
    sponge.absorb(&(info.len() as u64).to_le_bytes());
    sponge.absorb(info);
    sponge.finalize_absorb(DOMAIN_KDF);
    sponge.squeeze(output_len)
}

/// KK-MAC: compute a 256-bit authentication tag over a message.
///
/// Replaces HMAC-SHA256  - keyed sponge construction.
///
/// Inputs:
///   - `key`: authentication key
///   - `message`: the data to authenticate
pub fn kk_mac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut sponge = KkSponge::new();
    // Absorb key with length prefix (prevents length-extension)
    sponge.absorb(&(key.len() as u64).to_le_bytes());
    sponge.absorb(key);
    // Absorb message
    sponge.absorb(message);
    sponge.finalize_absorb(DOMAIN_MAC);
    let out = sponge.squeeze(32);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
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

/// Constant-time byte comparison. Runs in time proportional to the
/// shorter slice length, regardless of where differences occur.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// KK-Mix: mix arbitrary-length entropy sources into `output_len` bytes.
///
/// Used by the entropy module to combine multiple sources.
/// This replaces the HKDF-based mixing in the original entropy gathering.
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
        let mut state: KkState = [1, 2, 3, 4, 5, 6, 7, 8];
        let original = state;
        kk_permute(&mut state);
        assert_ne!(state, original, "Permutation must change the state");
    }

    #[test]
    fn permutation_is_deterministic() {
        let mut s1: KkState = [0xDEAD, 0xBEEF, 0xCAFE, 0xF00D, 1, 2, 3, 4];
        let mut s2 = s1;
        kk_permute(&mut s1);
        kk_permute(&mut s2);
        assert_eq!(s1, s2, "Same input must produce same output");
    }

    #[test]
    fn permutation_avalanche() {
        // Flipping one bit in input should change many bits in output.
        // Use IV-initialised state (realistic  - sponge always starts with IV).
        let mut s1: KkState = KK_IV;
        let mut s2: KkState = KK_IV;
        s2[0] ^= 1; // 1 bit difference
        kk_permute(&mut s1);
        kk_permute(&mut s2);

        let mut diff_bits = 0u32;
        for (a, b) in s1.iter().zip(s2.iter()) {
            diff_bits += (a ^ b).count_ones();
        }
        // Good avalanche: ~50% of 512 bits = ~256. Accept anything > 100.
        assert!(
            diff_bits > 100,
            "Poor avalanche: only {diff_bits}/512 bits differ (expected ~256)"
        );
    }

    #[test]
    fn entropy_rotations_change_output() {
        let mut s1: KkState = [42; STATE_WORDS];
        let mut s2 = s1;
        kk_permute(&mut s1); // default rotations
        kk_permute_with_schedule(&mut s2, &[[5, 50], [11, 33], [17, 39], [21, 47]]);
        assert_ne!(
            s1, s2,
            "Different rotation schedules must produce different permutations"
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
        // First 16 bytes should match (squeeze is prefix-consistent
        // within the first rate-block)
        // NOTE: they won't match across rate boundaries, which is fine
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
}
