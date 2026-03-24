// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

// KK Permutation  - WGSL Compute Shader
// Emulates u64 via vec2<u32> (lo, hi) since WGSL has no native u64.
// Each invocation processes one independent 25-word state (200 bytes).

// ── Layout ──────────────────────────────────────────────────────
// States buffer: N states × 25 words × 2 u32s = N × 50 u32s
// Rotations buffer: 15 pairs × 2 = 30 u32s
// Params: rounds (u32), num_states (u32)

struct Params {
    rounds: u32,
    num_states: u32,
};

@group(0) @binding(0) var<storage, read_write> states: array<u32>;
@group(0) @binding(1) var<storage, read>       rotations: array<u32>;
@group(0) @binding(2) var<uniform>             params: Params;

// ── u64 emulation via vec2<u32> (x=lo, y=hi) ───────────────────

fn u64_xor(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x ^ b.x, a.y ^ b.y);
}

fn u64_add(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    let lo = a.x + b.x;
    let carry = select(0u, 1u, lo < a.x);
    return vec2<u32>(lo, a.y + b.y + carry);
}

fn u64_or(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x | b.x, a.y | b.y);
}

fn u64_shl(v: vec2<u32>, s: u32) -> vec2<u32> {
    if s == 0u { return v; }
    if s >= 32u {
        return vec2<u32>(0u, v.x << (s - 32u));
    }
    return vec2<u32>(v.x << s, (v.y << s) | (v.x >> (32u - s)));
}

fn u64_shr(v: vec2<u32>, s: u32) -> vec2<u32> {
    if s == 0u { return v; }
    if s >= 32u {
        return vec2<u32>(v.y >> (s - 32u), 0u);
    }
    return vec2<u32>((v.x >> s) | (v.y << (32u - s)), v.y >> s);
}

fn u64_rotl(v: vec2<u32>, s: u32) -> vec2<u32> {
    let r = s & 63u;
    if r == 0u { return v; }
    return u64_xor(u64_shl(v, r), u64_shr(v, 64u - r));
}

// u64 wrapping multiply via 32-bit halves.
// Uses a.x*b.x (full 64-bit via 16-bit split) + cross terms positioned correctly.
fn u64_mul(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    // a = (a.y : a.x), b = (b.y : b.x) in little-endian
    // Result low  = low32(a.x * b.x)
    // Result high = high32(a.x * b.x) + low32(a.x * b.y) + low32(a.y * b.x)
    // We need the full 64-bit product of a.x * b.x, then add cross terms to high word.

    // Split a.x and b.x into 16-bit halves for full 32×32→64 multiply
    let al = a.x & 0xFFFFu;
    let ah = a.x >> 16u;
    let bl = b.x & 0xFFFFu;
    let bh = b.x >> 16u;

    // 16×16 partial products (each fits in u32)
    let ll = al * bl;
    let lh = al * bh;
    let hl = ah * bl;
    let hh = ah * bh;

    // Combine: result = hh:00:00 + 00:lh:00 + 00:hl:00 + ll
    // Column 0 (bits 0-15): just ll
    let r0 = ll & 0xFFFFu;

    // Column 1 (bits 16-31): upper half of ll + lower halves of lh and hl
    // Each term is at most 0xFFFF, so sum ≤ 3 * 0xFFFF = 0x2FFFD, fits in u32
    var mid = (ll >> 16u) + (lh & 0xFFFFu) + (hl & 0xFFFFu);
    let r1 = mid & 0xFFFFu;

    // Column 2 (bits 32-47): hh_lo + upper halves of lh and hl + carry from column 1
    // Each term ≤ 0xFFFF, carry ≤ 2, so sum ≤ 3 * 0xFFFF + 2, fits in u32
    mid = (hh & 0xFFFFu) + (lh >> 16u) + (hl >> 16u) + (mid >> 16u);
    let r2 = mid & 0xFFFFu;

    // Column 3 (bits 48-63): hh_hi + carry
    let r3 = (hh >> 16u) + (mid >> 16u);

    // Now add cross terms: a.x * b.y and a.y * b.x contribute to high word only
    let cross = a.x * b.y + a.y * b.x;
    let lo = r0 | (r1 << 16u);
    let hi = (r2 | (r3 << 16u)) + cross;

    return vec2<u32>(lo, hi);
}

fn u64_from_u32(v: u32) -> vec2<u32> {
    return vec2<u32>(v, 0u);
}

// ── KK Primitives ───────────────────────────────────────────────

// MFR: Multiply-Fold-Rotate
fn mfr(a: vec2<u32>, b: vec2<u32>, rot: u32) -> vec2<u32> {
    let b_odd = u64_or(b, vec2<u32>(1u, 0u));
    let product = u64_mul(a, b_odd);
    // fold: product ^ (product >> 32)
    let folded = vec2<u32>(product.x ^ product.y, product.y);
    return u64_rotl(folded, rot);
}

// DDR: Data-Dependent Rotation (constant-time)
fn ddr(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    // Fold all 64 bits into a 6-bit rotation selector
    let folded_lo = b.x ^ b.y;
    let s = (folded_lo ^ (folded_lo >> 16u) ^ (folded_lo >> 8u)) & 63u;

    var v = a;

    // 6 branchless conditional rotations by powers of 2
    let m0 = 0u - (s & 1u);          // all-ones or zero
    let r0 = u64_rotl(v, 1u);
    v = vec2<u32>((v.x & ~m0) | (r0.x & m0), (v.y & ~m0) | (r0.y & m0));

    let m1 = 0u - ((s >> 1u) & 1u);
    let r1 = u64_rotl(v, 2u);
    v = vec2<u32>((v.x & ~m1) | (r1.x & m1), (v.y & ~m1) | (r1.y & m1));

    let m2 = 0u - ((s >> 2u) & 1u);
    let r2 = u64_rotl(v, 4u);
    v = vec2<u32>((v.x & ~m2) | (r2.x & m2), (v.y & ~m2) | (r2.y & m2));

    let m3 = 0u - ((s >> 3u) & 1u);
    let r3 = u64_rotl(v, 8u);
    v = vec2<u32>((v.x & ~m3) | (r3.x & m3), (v.y & ~m3) | (r3.y & m3));

    let m4 = 0u - ((s >> 4u) & 1u);
    let r4 = u64_rotl(v, 16u);
    v = vec2<u32>((v.x & ~m4) | (r4.x & m4), (v.y & ~m4) | (r4.y & m4));

    let m5 = 0u - ((s >> 5u) & 1u);
    let r5 = u64_rotl(v, 32u);
    v = vec2<u32>((v.x & ~m5) | (r5.x & m5), (v.y & ~m5) | (r5.y & m5));

    return v;
}

// ── State I/O ───────────────────────────────────────────────────

fn state_load(base: u32, idx: u32) -> vec2<u32> {
    let off = base + idx * 2u;
    return vec2<u32>(states[off], states[off + 1u]);
}

fn state_store(base: u32, idx: u32, val: vec2<u32>) {
    let off = base + idx * 2u;
    states[off] = val.x;
    states[off + 1u] = val.y;
}

fn rot_load(idx: u32) -> vec2<u32> {
    // rotations are [pair_idx][0..1], stored as 30 u32s
    return vec2<u32>(rotations[idx * 2u], rotations[idx * 2u + 1u]);
}

// ── Diagonal index patterns (5×5 grid) ─────────────────────────

fn diag_idx(d: u32, i: u32) -> u32 {
    // DIAGS[d][i] for the 5×5 grid diagonals
    // [0,6,12,18,24], [1,7,13,19,20], [2,8,14,15,21], [3,9,10,16,22], [4,5,11,17,23]
    return (d + i * 5u + i * i) % 25u;
}

// Precomputed diagonal lookup  - faster than computing each time
fn diag(d: u32, i: u32) -> u32 {
    // Row 0: 0,6,12,18,24
    // Row 1: 1,7,13,19,20
    // Row 2: 2,8,14,15,21
    // Row 3: 3,9,10,16,22
    // Row 4: 4,5,11,17,23
    let table = array<u32, 25>(
        0u, 6u, 12u, 18u, 24u,
        1u, 7u, 13u, 19u, 20u,
        2u, 8u, 14u, 15u, 21u,
        3u, 9u, 10u, 16u, 22u,
        4u, 5u, 11u, 17u, 23u
    );
    return table[d * 5u + i];
}

// ── Round constant multipliers ──────────────────────────────────

const RC0: vec2<u32> = vec2<u32>(1u, 0u);                     // 1
const RC4: vec2<u32> = vec2<u32>(0x7F4A7C15u, 0x9E3779B9u);   // 0x9E3779B97F4A7C15
const RC12: vec2<u32> = vec2<u32>(0x8AED2A6Au, 0xB7E15162u);  // 0xB7E151628AED2A6A
const RC20: vec2<u32> = vec2<u32>(0x85A2F7A4u, 0x243F6A88u);  // 0x243F6A8885A2F7A4
const RC24: vec2<u32> = vec2<u32>(0x4B6A5240u, 0x298B075Bu);  // 0x298B075B4B6A5240

// ── KK Permutation ──────────────────────────────────────────────

@compute @workgroup_size(64)
fn kk_permute_kernel(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    if tid >= params.num_states { return; }

    let base = tid * 50u; // 25 words × 2 u32s each

    // Load full state into registers
    var s: array<vec2<u32>, 25>;
    for (var i = 0u; i < 25u; i++) {
        s[i] = state_load(base, i);
    }

    // Load rotation pairs into registers
    var rot: array<vec2<u32>, 15>;
    for (var i = 0u; i < 15u; i++) {
        rot[i] = rot_load(i);
    }

    for (var round = 0u; round < params.rounds; round++) {
        let round_v = u64_from_u32(round);

        // ── Row phase: 5 quintet-rounds ──
        for (var row = 0u; row < 5u; row++) {
            let b = row * 5u;
            let r0 = rot[row].x;
            let r1 = rot[row].y;

            s[b]     = mfr(s[b], s[b+1u], r0);
            s[b+2u]  = u64_xor(s[b+2u], s[b]);
            s[b+3u]  = ddr(s[b+3u], s[b+2u]);
            s[b+4u]  = mfr(s[b+4u], s[b+3u], r1);
            s[b+1u]  = u64_xor(s[b+1u], s[b+4u]);
        }

        // ── Column phase: 5 quintet-rounds ──
        for (var col = 0u; col < 5u; col++) {
            let r0 = rot[5u + col].x;
            let r1 = rot[5u + col].y;

            s[col]      = mfr(s[col], s[col+5u], r0);
            s[col+10u]  = u64_xor(s[col+10u], s[col]);
            s[col+15u]  = ddr(s[col+15u], s[col+10u]);
            s[col+20u]  = mfr(s[col+20u], s[col+15u], r1);
            s[col+5u]   = u64_xor(s[col+5u], s[col+20u]);
        }

        // ── Diagonal phase: 5 quintet-rounds ──
        for (var d = 0u; d < 5u; d++) {
            let i0 = diag(d, 0u);
            let i1 = diag(d, 1u);
            let i2 = diag(d, 2u);
            let i3 = diag(d, 3u);
            let i4 = diag(d, 4u);
            let r0 = rot[10u + d].x;
            let r1 = rot[10u + d].y;

            s[i0] = mfr(s[i0], s[i1], r0);
            s[i2] = u64_xor(s[i2], s[i0]);
            s[i3] = ddr(s[i3], s[i2]);
            s[i4] = mfr(s[i4], s[i3], r1);
            s[i1] = u64_xor(s[i1], s[i4]);
        }

        // ── Round constant injection ──
        s[0]  = u64_add(s[0],  round_v);
        s[4]  = u64_add(s[4],  u64_mul(round_v, RC4));
        s[12] = u64_add(s[12], u64_mul(round_v, RC12));
        s[20] = u64_add(s[20], u64_mul(round_v, RC20));
        s[24] = u64_add(s[24], u64_mul(round_v, RC24));

        // ── Intra-round re-keying every 8 rounds ──
        if round % 8u == 7u {
            for (var i = 0u; i < 19u; i++) { // RATE_WORDS = 19
                let cap_word = s[19u + (i % 6u)]; // CAPACITY_WORDS = 6
                s[i] = u64_xor(s[i], u64_rotl(cap_word, round));
            }
        }
    }

    // Store state back
    for (var i = 0u; i < 25u; i++) {
        state_store(base, i, s[i]);
    }
}
