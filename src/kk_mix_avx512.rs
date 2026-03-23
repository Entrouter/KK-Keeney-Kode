// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! AVX-512 horizontal-vectorized KK permutation kernel.
//!
//! Runs **8 independent sponge states simultaneously** using 512-bit SIMD.
//! Each `__m512i` register holds the same word index from 8 different states.
//!
//! Same math as scalar `kk_mix.rs`, same security, ~5-6× fewer clock cycles
//! on the permutation because:
//!   - DDR (6 conditional rotations in scalar) → ONE `VPROLVQ` instruction
//!   - MFR multiplication → `VPMULLQ` (8 × 64-bit multiplies in one op)
//!
//! Requires: AVX-512F + AVX-512DQ (Ice Lake+ / Zen 4+).
//! All functions are `#[target_feature(enable = "avx512f,avx512dq")]`
//! and `unsafe`, the caller must verify CPU support at runtime via
//! `is_x86_feature_detected!`.
//!
//! J.A. Keeney, Australia, 2026

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::kk_mix::{
    CAPACITY_WORDS, KkState, RATE_WORDS, STATE_WORDS,
};

/// 8 sponge states packed lane-wise: `state8[word_idx]` holds that
/// word from all 8 sponges in a single `__m512i`.
///
/// `#[repr(C)]` guarantees the array layout is predictable for SIMD loads/stores.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
pub(crate) struct KkState8(pub(crate) [__m512i; STATE_WORDS]);

#[cfg(target_arch = "x86_64")]
impl core::ops::Deref for KkState8 {
    type Target = [__m512i; STATE_WORDS];
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[cfg(target_arch = "x86_64")]
impl core::ops::DerefMut for KkState8 {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

/// Diagonal index patterns for the 5×5 grid (mirrors scalar DIAGS).
const DIAGS: [[usize; 5]; 5] = [
    [0, 6, 12, 18, 24],
    [1, 7, 13, 19, 20],
    [2, 8, 14, 15, 21],
    [3, 9, 10, 16, 22],
    [4, 5, 11, 17, 23],
];

// ─────────────────────────────────────────────────────────────────
//  Load / Store helpers
// ─────────────────────────────────────────────────────────────────

/// Pack 8 scalar `KkState`s into one `KkState8` (transpose).
///
/// # Safety
/// Requires AVX-512F.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn load_8_states(states: &[KkState; 8]) -> KkState8 {
    let mut packed = KkState8([_mm512_setzero_si512(); STATE_WORDS]);
    for w in 0..STATE_WORDS {
        packed[w] = _mm512_set_epi64(
            states[7][w] as i64,
            states[6][w] as i64,
            states[5][w] as i64,
            states[4][w] as i64,
            states[3][w] as i64,
            states[2][w] as i64,
            states[1][w] as i64,
            states[0][w] as i64,
        );
    }
    packed
}

/// Unpack a `KkState8` back into 8 scalar `KkState`s (transpose).
///
/// # Safety
/// Requires AVX-512F.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f")]
pub(crate) unsafe fn store_8_states(packed: &KkState8) -> [KkState; 8] {
    let mut states = [[0u64; STATE_WORDS]; 8];
    // Use a stack buffer aligned for 512-bit stores
    let mut buf = [0u64; 8];
    for w in 0..STATE_WORDS {
        _mm512_storeu_si512(buf.as_mut_ptr() as *mut __m512i, packed[w]);
        for lane in 0..8 {
            states[lane][w] = buf[lane];
        }
    }
    states
}

// ─────────────────────────────────────────────────────────────────
//  MFR ×8, Multiply-Fold-Rotate, 8 lanes
// ─────────────────────────────────────────────────────────────────

/// Vectorized MFR: `a ×₆₄ (b | 1)`, fold, rotate left by `rot`.
///
/// # Safety
/// Requires AVX-512F + AVX-512DQ (for `_mm512_mullo_epi64`).
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn mfr_x8(a: __m512i, b: __m512i, rot: u32) -> __m512i {
    // b | 1 → ensure odd (bijective)
    let b_odd = _mm512_or_si512(b, _mm512_set1_epi64(1));
    // product = a wrapping_mul (b | 1)
    let product = _mm512_mullo_epi64(a, b_odd);
    // fold = product ^ (product >> 32)
    let folded = _mm512_xor_si512(product, _mm512_srli_epi64(product, 32));
    // rotate left by rot (broadcast to all lanes for rolv)
    let vrot = _mm512_set1_epi64(rot as i64);
    _mm512_rolv_epi64(folded, vrot)
}

// ─────────────────────────────────────────────────────────────────
//  DDR ×8, Data-Dependent Rotation, 8 lanes
// ─────────────────────────────────────────────────────────────────

/// Vectorized DDR: rotate each lane of `a` left by a rotation amount derived
/// from ALL 64 bits of each lane of `b`.
///
/// Folds `b ^ (b >> 32) ^ (b >> 16) ^ (b >> 8)` then masks to 6 bits,
/// matching the scalar `ddr()` fix that ensures full-word sensitivity.
///
/// # Safety
/// Requires AVX-512F.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f")]
unsafe fn ddr_x8(a: __m512i, b: __m512i) -> __m512i {
    // Fold all 64 bits into the rotation selector (matches scalar ddr exactly)
    // Scalar: let folded = b ^ (b >> 32);
    //         let s = (folded ^ (folded >> 16) ^ (folded >> 8)) & 63;
    let folded = _mm512_xor_si512(b, _mm512_srli_epi64(b, 32));
    let shift = _mm512_xor_si512(
        _mm512_xor_si512(folded, _mm512_srli_epi64(folded, 16)),
        _mm512_srli_epi64(folded, 8),
    );
    let shift = _mm512_and_si512(shift, _mm512_set1_epi64(63));
    // Variable rotate left: each lane independently
    _mm512_rolv_epi64(a, shift)
}

// ─────────────────────────────────────────────────────────────────
//  Quintet-Round ×8
// ─────────────────────────────────────────────────────────────────

/// Vectorized quintet-round: same logic as scalar, 8 lanes in parallel.
///
/// ```text
/// a = MFR(a, b, rot0)
/// c = c ^ a
/// d = DDR(d, c)
/// e = MFR(e, d, rot1)
/// b = b ^ e
/// ```
///
/// # Safety
/// Requires AVX-512F + AVX-512DQ.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn quintet_round_x8(
    a: &mut __m512i,
    b: &mut __m512i,
    c: &mut __m512i,
    d: &mut __m512i,
    e: &mut __m512i,
    rot: [u32; 2],
) {
    *a = mfr_x8(*a, *b, rot[0]);
    *c = _mm512_xor_si512(*c, *a);
    *d = ddr_x8(*d, *c);
    *e = mfr_x8(*e, *d, rot[1]);
    *b = _mm512_xor_si512(*b, *e);
}

// ─────────────────────────────────────────────────────────────────
//  KK Permutation ×8, full permutation on 8 states in parallel
// ─────────────────────────────────────────────────────────────────

/// Apply the KK permutation to 8 states simultaneously.
///
/// Exact same algorithm as scalar `kk_permute_n`: row/col/diagonal
/// quintet-rounds, round constant injection, intra-round re-keying
/// every 8 rounds.
///
/// # Safety
/// Requires AVX-512F + AVX-512DQ.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512dq")]
pub(crate) unsafe fn kk_permute_n_x8(
    state: &mut KkState8,
    rotations: &[[u32; 2]; 15],
    rounds: usize,
) {
    // Running accumulators replace round × constant MUL with repeated ADD.
    // Produces identical values: 0, C, 2C, 3C, …  (wrapping u64).
    let vc0 = _mm512_set1_epi64(1i64);
    let vc4 = _mm512_set1_epi64(0x9E3779B97F4A7C15u64 as i64);
    let vc12 = _mm512_set1_epi64(0xB7E151628AED2A6Au64 as i64);
    let vc20 = _mm512_set1_epi64(0x243F6A8885A2F7A4u64 as i64);
    let vc24 = _mm512_set1_epi64(0x298B075B4B6A5240u64 as i64);
    let mut acc0 = _mm512_setzero_si512();
    let mut acc4 = _mm512_setzero_si512();
    let mut acc12 = _mm512_setzero_si512();
    let mut acc20 = _mm512_setzero_si512();
    let mut acc24 = _mm512_setzero_si512();

    for round in 0..rounds as u64 {
        // ── Row phase: 5 quintet-rounds ──
        for (row, rot) in rotations.iter().enumerate().take(5) {
            let base = row * 5;
            // Copy out 5 words (all 8 lanes each)
            let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                state[base],
                state[base + 1],
                state[base + 2],
                state[base + 3],
                state[base + 4],
            );
            quintet_round_x8(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, *rot);
            state[base] = s0;
            state[base + 1] = s1;
            state[base + 2] = s2;
            state[base + 3] = s3;
            state[base + 4] = s4;
        }

        // ── Column phase: 5 quintet-rounds ──
        for col in 0..5usize {
            let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                state[col],
                state[col + 5],
                state[col + 10],
                state[col + 15],
                state[col + 20],
            );
            quintet_round_x8(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rotations[5 + col]);
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
            quintet_round_x8(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rotations[10 + d]);
            state[i0] = s0;
            state[i1] = s1;
            state[i2] = s2;
            state[i3] = s3;
            state[i4] = s4;
        }

        // ── Round constant injection (corners + center of 5×5 grid) ──
        // Running accumulators: acc += C each round, identical to round × C.
        state[0] = _mm512_add_epi64(state[0], acc0);
        state[4] = _mm512_add_epi64(state[4], acc4);
        state[12] = _mm512_add_epi64(state[12], acc12);
        state[20] = _mm512_add_epi64(state[20], acc20);
        state[24] = _mm512_add_epi64(state[24], acc24);
        acc0 = _mm512_add_epi64(acc0, vc0);
        acc4 = _mm512_add_epi64(acc4, vc4);
        acc12 = _mm512_add_epi64(acc12, vc12);
        acc20 = _mm512_add_epi64(acc20, vc20);
        acc24 = _mm512_add_epi64(acc24, vc24);

        // ── Intra-round re-keying every 8 rounds ──
        if round % 8 == 7 {
            for i in 0..RATE_WORDS {
                let cap = state[RATE_WORDS + (i % CAPACITY_WORDS)];
                let vround = _mm512_set1_epi64(round as i64);
                let rotated = _mm512_rolv_epi64(cap, vround);
                state[i] = _mm512_xor_si512(state[i], rotated);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod tests {
    use super::*;
    use crate::kk_mix::{KK_IV, DEFAULT_ROTATIONS, KkState, ROUNDS, KDF_SQUEEZE_ROUNDS, kk_permute_n};

    #[test]
    fn avx512_matches_scalar_full_rounds() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512dq") {
            eprintln!("Skipping AVX-512 test: CPU does not support AVX-512F+DQ");
            return;
        }

        // Build 8 distinct states
        let mut scalar_states: [KkState; 8] = [KK_IV; 8];
        for (i, state) in scalar_states.iter_mut().enumerate() {
            state[0] ^= (i as u64).wrapping_mul(0x1111_1111_1111_1111);
            state[12] ^= (i as u64).wrapping_mul(0xAAAA_BBBB_CCCC_DDDD);
        }

        // Run scalar on each
        let mut expected = scalar_states;
        for s in expected.iter_mut() {
            kk_permute_n(s, &DEFAULT_ROTATIONS, ROUNDS);
        }

        // Run AVX-512 on all 8 simultaneously
        unsafe {
            let mut packed = load_8_states(&scalar_states);
            kk_permute_n_x8(&mut packed, &DEFAULT_ROTATIONS, ROUNDS);
            let got = store_8_states(&packed);

            for lane in 0..8 {
                assert_eq!(
                    got[lane], expected[lane],
                    "AVX-512 lane {lane} diverged from scalar (full {ROUNDS} rounds)"
                );
            }
        }
    }

    #[test]
    fn avx512_matches_scalar_kdf_rounds() {
        if !is_x86_feature_detected!("avx512f") || !is_x86_feature_detected!("avx512dq") {
            eprintln!("Skipping AVX-512 test: CPU does not support AVX-512F+DQ");
            return;
        }

        let mut scalar_states: [KkState; 8] = [KK_IV; 8];
        for (i, state) in scalar_states.iter_mut().enumerate() {
            state[0] ^= (i as u64).wrapping_mul(0xDEAD_BEEF_CAFE_BABE);
        }

        let mut expected = scalar_states;
        for s in expected.iter_mut() {
            kk_permute_n(s, &DEFAULT_ROTATIONS, KDF_SQUEEZE_ROUNDS);
        }

        unsafe {
            let mut packed = load_8_states(&scalar_states);
            kk_permute_n_x8(&mut packed, &DEFAULT_ROTATIONS, KDF_SQUEEZE_ROUNDS);
            let got = store_8_states(&packed);

            for lane in 0..8 {
                assert_eq!(
                    got[lane], expected[lane],
                    "AVX-512 lane {lane} diverged from scalar ({KDF_SQUEEZE_ROUNDS} rounds)"
                );
            }
        }
    }
}
