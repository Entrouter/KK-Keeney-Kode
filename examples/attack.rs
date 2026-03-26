//! KK Cryptanalysis: adversarial self-attack
//!
//! Attempts to find weaknesses in the KK permutation by:
//!   1. DDR rotation selector collision rate
//!   2. Reduced-round differential propagation
//!   3. Capacity word diffusion measurement
//!   4. Avalanche defect detection
//!   5. MFR algebraic bias search
//!   6. Round-constant-free word distinguisher
//!
//! Run: cargo run --release --example attack

use std::time::Instant;

// ─────────────────── Re-implemented primitives ───────────────────
// (originals are private in kk_mix.rs, so we copy them exactly)

const STATE_WORDS: usize = 25;
const RATE_WORDS: usize = 19;
const CAPACITY_WORDS: usize = 6;

const DEFAULT_ROTATIONS: [[u32; 2]; 15] = [
    [7, 41], [13, 29], [19, 37], [23, 43], [3, 53],
    [11, 47], [17, 39], [5, 59], [31, 49], [9, 51],
    [15, 33], [21, 45], [27, 35], [1, 57], [25, 55],
];

const DIAGS: [[usize; 5]; 5] = [
    [0,  6, 12, 18, 24],
    [1,  7, 13, 19, 20],
    [2,  8, 14, 15, 21],
    [3,  9, 10, 16, 22],
    [4,  5, 11, 17, 23],
];

const KK_IV: [u64; STATE_WORDS] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1, 0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179, 0xCBBB9D5DC1059ED8,
    0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
    0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7,
    0x47B5481DBEFA4FA4, 0xAE5F9156E7B6D99B, 0xCF6C85D39D1A1E15,
    0x2F73477D6A4563CA, 0x6D1826CAFD82E1ED, 0x8B43D4570A51B936,
    0xE360B596DC380C3F, 0x1C456002CE13E9F8, 0x6F19633143A0AF0E,
    0xD94EBEB1AB313933,
];

type KkState = [u64; STATE_WORDS];

#[inline(always)]
fn mfr(a: u64, b: u64, rot: u32) -> u64 {
    let product = a.wrapping_mul(b | 1);
    let folded = product ^ (product >> 32);
    folded.rotate_left(rot)
}

#[inline(always)]
fn ddr(a: u64, b: u64) -> u64 {
    let folded = b ^ (b >> 32);
    let s = (folded ^ (folded >> 16) ^ (folded >> 8)) & 63;
    let mut r = a;
    // Branchless conditional rotations
    if s & 1 != 0 { r = r.rotate_left(1); }
    if s & 2 != 0 { r = r.rotate_left(2); }
    if s & 4 != 0 { r = r.rotate_left(4); }
    if s & 8 != 0 { r = r.rotate_left(8); }
    if s & 16 != 0 { r = r.rotate_left(16); }
    if s & 32 != 0 { r = r.rotate_left(32); }
    r
}

/// Extract the 6-bit rotation selector from DDR's second argument
#[inline(always)]
fn ddr_selector(b: u64) -> u64 {
    let folded = b ^ (b >> 32);
    (folded ^ (folded >> 16) ^ (folded >> 8)) & 63
}

#[inline(always)]
fn quintet_round(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64, e: &mut u64, rot: [u32; 2]) {
    *a = mfr(*a, *b, rot[0]);
    *c ^= *a;
    *d = ddr(*d, *c);
    *e = mfr(*e, *d, rot[1]);
    *b ^= *e;
}

fn kk_permute_n(state: &mut KkState, rotations: &[[u32; 2]; 15], rounds: usize) {
    for round in 0..rounds as u64 {
        // Row phase
        for (row, rot) in rotations.iter().enumerate().take(5) {
            let base = row * 5;
            let (mut s0, mut s1, mut s2, mut s3, mut s4) =
                (state[base], state[base+1], state[base+2], state[base+3], state[base+4]);
            quintet_round(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, *rot);
            state[base] = s0; state[base+1] = s1; state[base+2] = s2;
            state[base+3] = s3; state[base+4] = s4;
        }
        // Column phase
        for col in 0..5usize {
            let (mut s0, mut s1, mut s2, mut s3, mut s4) =
                (state[col], state[col+5], state[col+10], state[col+15], state[col+20]);
            quintet_round(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rotations[5 + col]);
            state[col] = s0; state[col+5] = s1; state[col+10] = s2;
            state[col+15] = s3; state[col+20] = s4;
        }
        // Diagonal phase
        for d in 0..5usize {
            let [i0, i1, i2, i3, i4] = DIAGS[d];
            let (mut s0, mut s1, mut s2, mut s3, mut s4) =
                (state[i0], state[i1], state[i2], state[i3], state[i4]);
            quintet_round(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rotations[10 + d]);
            state[i0] = s0; state[i1] = s1; state[i2] = s2;
            state[i3] = s3; state[i4] = s4;
        }
        // Round constant injection
        state[0] = state[0].wrapping_add(round);
        state[4] = state[4].wrapping_add(round.wrapping_mul(0x9E3779B97F4A7C15));
        state[12] = state[12].wrapping_add(round.wrapping_mul(0xB7E151628AED2A6A));
        state[20] = state[20].wrapping_add(round.wrapping_mul(0x243F6A8885A2F7A4));
        state[24] = state[24].wrapping_add(round.wrapping_mul(0x298B075B4B6A5240));
        // Intra-round re-keying every 8 rounds
        if round % 8 == 7 {
            for i in 0..RATE_WORDS {
                state[i] ^= state[RATE_WORDS + (i % CAPACITY_WORDS)].rotate_left(round as u32);
            }
        }
    }
}

fn hamming_distance_u64(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

fn state_hamming(a: &KkState, b: &KkState) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| hamming_distance_u64(*x, *y)).sum()
}

fn capacity_hamming(a: &KkState, b: &KkState) -> u32 {
    (RATE_WORDS..STATE_WORDS).map(|i| hamming_distance_u64(a[i], b[i])).sum()
}

fn rate_hamming(a: &KkState, b: &KkState) -> u32 {
    (0..RATE_WORDS).map(|i| hamming_distance_u64(a[i], b[i])).sum()
}

/// Simple xorshift64 PRNG for reproducible tests
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self { Self(seed) }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn random_state(&mut self) -> KkState {
        let mut s = [0u64; STATE_WORDS];
        for w in s.iter_mut() { *w = self.next(); }
        s
    }
}

// ───────────────────────── ATTACK 1 ─────────────────────────────
// DDR rotation selector collision rate
//
// Theory: the fold b -> 6 bits is GF(2)-linear, so for random delta_b,
// Pr[selector(b) == selector(b ^ delta_b)] = 1/64 = 0.015625
//
// If the collision rate is HIGHER than 1/64, the DDR is weaker than
// expected because differentials pass through it more easily.

fn attack_1_ddr_collision() {
    println!("=== ATTACK 1: DDR Rotation Selector Collision Rate ===");
    let mut rng = Rng::new(0xDEADBEEF_CAFEBABE);
    let trials = 10_000_000u64;
    let mut collisions = 0u64;

    for _ in 0..trials {
        let b = rng.next();
        let delta = rng.next(); // random non-zero difference
        if delta == 0 { continue; }
        let b2 = b ^ delta;
        if ddr_selector(b) == ddr_selector(b2) {
            collisions += 1;
        }
    }

    let rate = collisions as f64 / trials as f64;
    let expected = 1.0 / 64.0;
    println!("  Trials:    {trials}");
    println!("  Collisions: {collisions}");
    println!("  Rate:      {rate:.8}");
    println!("  Expected:  {expected:.8} (1/64)");
    println!("  Ratio:     {:.4}x expected", rate / expected);

    if rate > expected * 1.05 {
        println!("  !! ELEVATED collision rate detected !!");
    } else {
        println!("  [OK] Collision rate matches theoretical 1/64");
    }

    // Also test structured differences: single-bit flips
    println!("\n  Single-bit flip collision rates:");
    for bit in [0, 1, 7, 8, 15, 16, 31, 32, 47, 48, 63] {
        let mut col = 0u64;
        let delta: u64 = 1 << bit;
        for _ in 0..1_000_000 {
            let b = rng.next();
            if ddr_selector(b) == ddr_selector(b ^ delta) {
                col += 1;
            }
        }
        let r = col as f64 / 1_000_000.0;
        let flag = if r > 0.05 { " !! HIGH" } else { "" };
        println!("    bit {bit:2}: collision rate = {r:.6}{flag}");
    }
    println!();
}

// ───────────────────────── ATTACK 2 ─────────────────────────────
// Reduced-round differential propagation
//
// For 1, 2, 4, 8 rounds: flip a single bit in one rate word,
// measure how many output bits change. Looking for:
// - Incomplete diffusion (average Hamming distance < 800 out of 1600)
// - Bias in specific words (some words barely change)

fn attack_2_reduced_round_differential() {
    println!("=== ATTACK 2: Reduced-Round Differential Propagation ===");
    let mut rng = Rng::new(0x1234567890ABCDEF);
    let trials = 50_000;

    for rounds in [1, 2, 3, 4, 8, 16, 20, 32] {
        let mut total_hamming = 0u64;
        let mut min_hamming = u32::MAX;
        let mut max_hamming = 0u32;
        let mut cap_total = 0u64;
        let mut per_word_hamming = [0u64; STATE_WORDS];

        for _ in 0..trials {
            let state = rng.random_state();
            // Flip one random bit in a random rate word
            let target_word = (rng.next() as usize) % RATE_WORDS;
            let target_bit = (rng.next() as usize) % 64;

            let mut s1 = state;
            let mut s2 = state;
            s2[target_word] ^= 1u64 << target_bit;

            kk_permute_n(&mut s1, &DEFAULT_ROTATIONS, rounds);
            kk_permute_n(&mut s2, &DEFAULT_ROTATIONS, rounds);

            let h = state_hamming(&s1, &s2);
            total_hamming += h as u64;
            min_hamming = min_hamming.min(h);
            max_hamming = max_hamming.max(h);
            cap_total += capacity_hamming(&s1, &s2) as u64;

            for w in 0..STATE_WORDS {
                per_word_hamming[w] += hamming_distance_u64(s1[w], s2[w]) as u64;
            }
        }

        let avg = total_hamming as f64 / trials as f64;
        let ideal = 800.0; // half of 1600 bits
        let cap_avg = cap_total as f64 / trials as f64;
        let cap_ideal = 192.0; // half of 384 capacity bits

        println!("  Rounds={rounds:2}: avg={avg:.1}/{ideal} (ideal)  min={min_hamming} max={max_hamming}  cap_avg={cap_avg:.1}/{cap_ideal}");

        // Show per-word breakdown for low round counts
        if rounds <= 4 {
            println!("    Per-word avg Hamming (ideal=32.0 each):");
            for row in 0..5 {
                print!("      ");
                for col in 0..5 {
                    let w = row * 5 + col;
                    let wavg = per_word_hamming[w] as f64 / trials as f64;
                    let tag = if w >= RATE_WORDS { "C" } else { " " }; // C = capacity
                    print!("[{w:2}{tag}]{wavg:5.1}  ");
                }
                println!();
            }
        }
    }
    println!();
}

// ───────────────────────── ATTACK 3 ─────────────────────────────
// Capacity isolation: can we find an input difference that affects
// ONLY rate words and leaves capacity words unchanged?
//
// This would be catastrophic: it means inner collisions are free.
// We search for this by testing many single-bit differences and
// checking if any leave the capacity perfectly untouched.

fn attack_3_capacity_isolation() {
    println!("=== ATTACK 3: Capacity Isolation Search ===");
    let mut rng = Rng::new(0xAAAABBBBCCCCDDDD);

    for rounds in [1, 2, 4, 8, 32] {
        let mut zero_cap_diffs = 0u64;
        let mut min_cap_hamming = u32::MAX;
        let trials = 100_000;

        for _ in 0..trials {
            let state = rng.random_state();
            let target_word = (rng.next() as usize) % RATE_WORDS;
            let target_bit = (rng.next() as usize) % 64;

            let mut s1 = state;
            let mut s2 = state;
            s2[target_word] ^= 1u64 << target_bit;

            kk_permute_n(&mut s1, &DEFAULT_ROTATIONS, rounds);
            kk_permute_n(&mut s2, &DEFAULT_ROTATIONS, rounds);

            let cap_h = capacity_hamming(&s1, &s2);
            if cap_h == 0 {
                zero_cap_diffs += 1;
            }
            min_cap_hamming = min_cap_hamming.min(cap_h);
        }

        let prob = zero_cap_diffs as f64 / trials as f64;
        println!("  Rounds={rounds:2}: zero-capacity-diff={zero_cap_diffs}/{trials} (p={prob:.2e})  min_cap_hamming={min_cap_hamming}");

        if zero_cap_diffs > 0 && rounds >= 4 {
            println!("  !! CRITICAL: Found input differences that don't reach capacity !!");
        }
    }
    println!();
}

// ───────────────────────── ATTACK 4 ─────────────────────────────
// Strict Avalanche Criterion (SAC) test
//
// For each input bit position, flip it and measure whether each
// output bit changes with probability 0.5. Deviations from 0.5
// indicate structural bias.

fn attack_4_sac() {
    println!("=== ATTACK 4: Strict Avalanche Criterion (32 rounds) ===");
    let mut rng = Rng::new(0x0F0F0F0F0F0F0F0F);
    let trials = 20_000;

    // Test a representative set of input bit positions
    let test_positions: Vec<(usize, usize)> = vec![
        (0, 0), (0, 31), (0, 63),    // word 0 (rate, first)
        (9, 0), (9, 32),              // word 9 (rate, middle)
        (18, 0), (18, 63),            // word 18 (rate, last)
    ];

    let mut worst_bias = 0.0f64;
    let mut worst_pos = (0, 0, 0); // (input_word, input_bit, output_bit)

    for &(in_word, in_bit) in &test_positions {
        // Count how many times each output bit flips
        let mut flip_count = [0u32; 1600];

        for _ in 0..trials {
            let state = rng.random_state();
            let mut s1 = state;
            let mut s2 = state;
            s2[in_word] ^= 1u64 << in_bit;

            kk_permute_n(&mut s1, &DEFAULT_ROTATIONS, 32);
            kk_permute_n(&mut s2, &DEFAULT_ROTATIONS, 32);

            for w in 0..STATE_WORDS {
                let diff = s1[w] ^ s2[w];
                for b in 0..64 {
                    if diff & (1u64 << b) != 0 {
                        flip_count[w * 64 + b] += 1;
                    }
                }
            }
        }

        // Find max deviation from 0.5
        let mut max_dev = 0.0f64;
        let mut max_bit = 0;
        for (i, &count) in flip_count.iter().enumerate() {
            let prob = count as f64 / trials as f64;
            let dev = (prob - 0.5).abs();
            if dev > max_dev {
                max_dev = dev;
                max_bit = i;
            }
        }

        if max_dev > worst_bias {
            worst_bias = max_dev;
            worst_pos = (in_word, in_bit, max_bit);
        }

        println!("  Input word[{in_word}] bit {in_bit}: max_bias={max_dev:.6} at output bit {max_bit}");
    }

    // Statistical threshold: for 20000 trials, 3-sigma deviation is ~0.0106
    let sigma3 = 3.0 / (2.0 * (trials as f64).sqrt());
    println!("\n  Worst bias overall: {worst_bias:.6} (at in_w={}, in_b={}, out_b={})", worst_pos.0, worst_pos.1, worst_pos.2);
    println!("  3-sigma threshold: {sigma3:.6}");
    if worst_bias > sigma3 * 2.0 {
        println!("  !! SAC VIOLATION: bias exceeds 6-sigma !!");
    } else {
        println!("  [OK] All biases within statistical noise");
    }
    println!();
}

// ───────────────────────── ATTACK 5 ─────────────────────────────
// MFR output bias: test whether MFR produces output bits with
// uniform distribution when fed random inputs.
//
// Specifically: does bit k of MFR(a, b, rot) have probability 0.5
// of being set? Bias here would indicate algebraic weakness.

fn attack_5_mfr_bias() {
    println!("=== ATTACK 5: MFR Output Bit Bias ===");
    let mut rng = Rng::new(0xFEDCBA9876543210);
    let trials = 5_000_000u64;

    for &rot in &[7u32, 41, 1, 63, 32] {
        let mut bit_count = [0u64; 64];
        for _ in 0..trials {
            let a = rng.next();
            let b = rng.next();
            let result = mfr(a, b, rot);
            for bit in 0..64 {
                if result & (1u64 << bit) != 0 {
                    bit_count[bit] += 1;
                }
            }
        }

        let mut max_bias = 0.0f64;
        let mut max_bit = 0;
        for bit in 0..64 {
            let prob = bit_count[bit] as f64 / trials as f64;
            let bias = (prob - 0.5).abs();
            if bias > max_bias {
                max_bias = bias;
                max_bit = bit;
            }
        }

        // 3-sigma for 5M trials
        let sigma3 = 3.0 / (2.0 * (trials as f64).sqrt());
        let flag = if max_bias > sigma3 * 2.0 { " !! BIASED" } else { "" };
        println!("  rot={rot:2}: max_bias={max_bias:.7} at bit {max_bit:2} (3sig={sigma3:.7}){flag}");
    }
    println!();
}

// ───────────────────────── ATTACK 6 ─────────────────────────────
// Round constant coverage: words [1,2,3,5,6,7,8,9,10,11,13,14,15,16,17,18,19,21,22,23]
// get NO direct round constants. Can we distinguish these "dark" words
// from the "lit" words [0,4,12,20,24] after reduced rounds?
//
// Measure: for a zero input state (all zeros), how quickly do the
// dark words become statistically indistinguishable from the lit words?

fn attack_6_round_constant_coverage() {
    println!("=== ATTACK 6: Round Constant Coverage (Dark vs Lit Words) ===");
    let lit_words: Vec<usize> = vec![0, 4, 12, 20, 24];

    for rounds in [1, 2, 4, 8, 16, 32] {
        let mut state = KK_IV;
        kk_permute_n(&mut state, &DEFAULT_ROTATIONS, rounds);

        // Check population count of each word (ideal = ~32)
        let mut lit_avg_pop = 0.0f64;
        let mut dark_avg_pop = 0.0f64;
        let mut lit_count = 0;
        let mut dark_count = 0;

        for w in 0..STATE_WORDS {
            let pop = state[w].count_ones() as f64;
            if lit_words.contains(&w) {
                lit_avg_pop += pop;
                lit_count += 1;
            } else {
                dark_avg_pop += pop;
                dark_count += 1;
            }
        }
        lit_avg_pop /= lit_count as f64;
        dark_avg_pop /= dark_count as f64;

        println!("  Rounds={rounds:2}: lit_avg_popcount={lit_avg_pop:.2}  dark_avg_popcount={dark_avg_pop:.2}  diff={:.2}", (lit_avg_pop - dark_avg_pop).abs());
    }
    println!();
}

// ───────────────────────── ATTACK 7 ─────────────────────────────
// Row 4 isolation: the bottom row (words 20-24, all capacity) only
// mixes with itself during the row phase. Test whether this creates
// a detectable weakness in capacity mixing.
//
// Compare: diffusion from rate into capacity vs capacity into rate
// after 1 round. If asymmetric, the high rate ratio (~76%) leaves
// capacity more vulnerable.

fn attack_7_row4_capacity_mixing() {
    println!("=== ATTACK 7: Row 4 Capacity Mixing Asymmetry ===");
    let mut rng = Rng::new(0x1111222233334444);
    let trials = 100_000;

    for rounds in [1, 2, 4] {
        // Test A: flip 1 rate bit, measure change in capacity
        let mut rate_to_cap_total = 0u64;
        // Test B: flip 1 capacity bit, measure change in rate
        let mut cap_to_rate_total = 0u64;

        for _ in 0..trials {
            let state = rng.random_state();

            // A: rate -> capacity
            {
                let mut s1 = state;
                let mut s2 = state;
                let w = (rng.next() as usize) % RATE_WORDS;
                s2[w] ^= 1u64 << ((rng.next() as usize) % 64);
                kk_permute_n(&mut s1, &DEFAULT_ROTATIONS, rounds);
                kk_permute_n(&mut s2, &DEFAULT_ROTATIONS, rounds);
                rate_to_cap_total += capacity_hamming(&s1, &s2) as u64;
            }

            // B: capacity -> rate
            {
                let mut s1 = state;
                let mut s2 = state;
                let w = RATE_WORDS + ((rng.next() as usize) % CAPACITY_WORDS);
                s2[w] ^= 1u64 << ((rng.next() as usize) % 64);
                kk_permute_n(&mut s1, &DEFAULT_ROTATIONS, rounds);
                kk_permute_n(&mut s2, &DEFAULT_ROTATIONS, rounds);
                cap_to_rate_total += rate_hamming(&s1, &s2) as u64;
            }
        }

        let a_avg = rate_to_cap_total as f64 / trials as f64;
        let b_avg = cap_to_rate_total as f64 / trials as f64;
        let a_ideal = 192.0; // half of 384 capacity bits
        let b_ideal = 608.0; // half of 1216 rate bits
        let a_pct = a_avg / a_ideal * 100.0;
        let b_pct = b_avg / b_ideal * 100.0;

        println!("  Rounds={rounds}: rate->cap={a_avg:.1}/{a_ideal} ({a_pct:.1}%)  cap->rate={b_avg:.1}/{b_ideal} ({b_pct:.1}%)");
        if a_pct < 50.0 && rounds >= 2 {
            println!("  !! WEAK: rate changes don't reach capacity after {rounds} rounds !!");
        }
    }
    println!();
}

// ───────────────────────── ATTACK 8 ─────────────────────────────
// KDF squeeze round gap: compare 20-round squeeze output distribution
// vs 32-round squeeze output. If distinguishable, the KDF is weaker
// than the full hash.

fn attack_8_kdf_squeeze_gap() {
    println!("=== ATTACK 8: KDF Squeeze Round Gap (20 vs 32) ===");
    let mut rng = Rng::new(0x5555666677778888);
    let trials = 100_000;

    // For random states, permute with 20 rounds and 32 rounds,
    // measure statistical distance of the rate output.
    let mut pop_count_20 = [0u64; 65]; // distribution of popcount per word
    let mut pop_count_32 = [0u64; 65];

    for _ in 0..trials {
        let state = rng.random_state();

        let mut s20 = state;
        kk_permute_n(&mut s20, &DEFAULT_ROTATIONS, 20);

        let mut s32 = state;
        kk_permute_n(&mut s32, &DEFAULT_ROTATIONS, 32);

        // Sample first rate word
        let pc20 = s20[0].count_ones() as usize;
        let pc32 = s32[0].count_ones() as usize;
        pop_count_20[pc20] += 1;
        pop_count_32[pc32] += 1;
    }

    // Chi-squared test against binomial(64, 0.5)
    let chi2_20 = chi_squared_popcount(&pop_count_20, trials);
    let chi2_32 = chi_squared_popcount(&pop_count_32, trials);

    println!("  Chi-squared (popcount of word[0]):");
    println!("    20 rounds: chi2 = {chi2_20:.2}");
    println!("    32 rounds: chi2 = {chi2_32:.2}");
    println!("    (df=64, critical value at p=0.01 is ~95.6)");

    if chi2_20 > 95.6 {
        println!("  !! 20-round output shows distributional bias !!");
    } else {
        println!("  [OK] 20-round output appears uniformly distributed");
    }
    println!();
}

fn chi_squared_popcount(observed: &[u64; 65], total: u64) -> f64 {
    // Expected: Binomial(64, 0.5)
    let n = total as f64;
    let mut chi2 = 0.0;
    for k in 0..65 {
        let expected = n * binom_pmf(64, k);
        if expected > 0.0 {
            let diff = observed[k] as f64 - expected;
            chi2 += (diff * diff) / expected;
        }
    }
    chi2
}

fn binom_pmf(n: usize, k: usize) -> f64 {
    // log-space computation to avoid overflow
    let mut log_p = 0.0f64;
    for i in 0..k {
        log_p += ((n - i) as f64).ln() - ((i + 1) as f64).ln();
    }
    log_p -= (n as f64) * 2.0f64.ln();
    log_p.exp()
}

// ───────────────────────── ATTACK 9 ─────────────────────────────
// Differential trail through a single quintet: for chosen differences
// in (a,b), measure output difference distribution. Looking for
// high-probability differential characteristics.

fn attack_9_quintet_differential() {
    println!("=== ATTACK 9: Single Quintet Differential Trail Search ===");
    let mut rng = Rng::new(0x9999AAAA_BBBBCCCC);
    let rot = [7u32, 41]; // first default rotation pair
    let trials = 2_000_000u64;

    // Test: single-bit difference in word b (index 1 of quintet)
    // The quintet order is: a, b, c, d, e -> positions 0,1,2,3,4
    // We flip bit 0 of b and measure the output Hamming distance.
    println!("  Single-bit diff in b (word 1 of quintet):");
    let mut hamming_dist = [0u64; 321]; // max possible = 5*64 = 320

    for _ in 0..trials {
        let (mut a1, mut b1, mut c1, mut d1, mut e1) =
            (rng.next(), rng.next(), rng.next(), rng.next(), rng.next());
        let (mut a2, mut b2, mut c2, mut d2, mut e2) = (a1, b1, c1, d1, e1);
        b2 ^= 1; // flip bit 0

        quintet_round(&mut a1, &mut b1, &mut c1, &mut d1, &mut e1, rot);
        quintet_round(&mut a2, &mut b2, &mut c2, &mut d2, &mut e2, rot);

        let h = hamming_distance_u64(a1, a2) + hamming_distance_u64(b1, b2)
            + hamming_distance_u64(c1, c2) + hamming_distance_u64(d1, d2)
            + hamming_distance_u64(e1, e2);
        hamming_dist[h as usize] += 1;
    }

    let avg_h: f64 = hamming_dist.iter().enumerate()
        .map(|(h, &count)| h as f64 * count as f64).sum::<f64>() / trials as f64;
    let min_h = hamming_dist.iter().position(|&c| c > 0).unwrap();
    let max_h = hamming_dist.iter().rposition(|&c| c > 0).unwrap();

    println!("    avg Hamming = {avg_h:.1} / 160 (ideal)");
    println!("    min = {min_h}, max = {max_h}");

    // Check: did we ever see Hamming distance = 0 (perfect collision)?
    if hamming_dist[0] > 0 {
        println!("    !! COLLISION FOUND: {0} cases with zero difference !!", hamming_dist[0]);
    }

    // Check low-hamming events
    let low_h: u64 = hamming_dist[..20].iter().sum();
    let low_rate = low_h as f64 / trials as f64;
    println!("    Pr[h < 20] = {low_rate:.2e}");
    if low_rate > 1e-4 {
        println!("    !! ELEVATED low-hamming probability through single quintet !!");
    }

    // Test: zero diff propagation. Start with diff only in a (word 0).
    println!("\n  Single-bit diff in a (word 0 of quintet):");
    let mut zero_out = 0u64;
    let mut total_h: u64 = 0;

    for _ in 0..trials {
        let (mut a1, mut b1, mut c1, mut d1, mut e1) =
            (rng.next(), rng.next(), rng.next(), rng.next(), rng.next());
        let (mut a2, mut b2, mut c2, mut d2, mut e2) = (a1, b1, c1, d1, e1);
        a2 ^= 1;

        quintet_round(&mut a1, &mut b1, &mut c1, &mut d1, &mut e1, rot);
        quintet_round(&mut a2, &mut b2, &mut c2, &mut d2, &mut e2, rot);

        let h = hamming_distance_u64(a1, a2) + hamming_distance_u64(b1, b2)
            + hamming_distance_u64(c1, c2) + hamming_distance_u64(d1, d2)
            + hamming_distance_u64(e1, e2);
        total_h += h as u64;
        if h == 0 { zero_out += 1; }
    }

    let a_avg = total_h as f64 / trials as f64;
    println!("    avg Hamming = {a_avg:.1} / 160 (ideal)");
    println!("    zero-output-diff = {zero_out}");
    println!();
}

// ───────────────────────── ATTACK 10 ────────────────────────────
// DDR linearity exploit: since the selector fold is GF(2)-linear,
// we can predict exactly which differences cancel the rotation change.
// For the FULL DDR operation (not just selector), does this linearity
// create exploitable differential properties?

fn attack_10_ddr_differential() {
    println!("=== ATTACK 10: DDR Full Differential Properties ===");
    let mut rng = Rng::new(0xAAAA_5555_DEAD_BEEF);
    let trials = 5_000_000u64;

    // When ddr_selector(b) == ddr_selector(b'), the rotation amount
    // is identical, so ddr(a, b) == ddr(a, b') for any a.
    // This means: if we can find delta_b such that the selector collides,
    // the DDR becomes transparent to differentials in the first arg.
    //
    // Measure: among selector-colliding pairs, what's the probability
    // that ddr(a, b) ^ ddr(a ^ delta_a, b ^ delta_b) = rotate(delta_a, s)?

    let mut exact_predictions = 0u64;
    let mut selector_collisions = 0u64;

    for _ in 0..trials {
        let a = rng.next();
        let b = rng.next();
        let delta_a = rng.next();
        let delta_b = rng.next();
        if delta_b == 0 { continue; }

        let s1 = ddr_selector(b);
        let s2 = ddr_selector(b ^ delta_b);

        if s1 == s2 {
            selector_collisions += 1;
            // When selectors match, ddr(a, b) = rotate(a, s1)
            // and ddr(a ^ delta_a, b ^ delta_b) = rotate(a ^ delta_a, s1)
            // so the XOR difference = rotate(delta_a, s1)
            let out1 = ddr(a, b);
            let out2 = ddr(a ^ delta_a, b ^ delta_b);
            let predicted = ddr(delta_a, b); // rotate(delta_a, s1)
            if out1 ^ out2 == predicted {
                exact_predictions += 1;
            }
        }
    }

    let pred_rate = if selector_collisions > 0 {
        exact_predictions as f64 / selector_collisions as f64
    } else { 0.0 };

    println!("  Selector collisions: {selector_collisions} / {trials} ({:.4})", selector_collisions as f64 / trials as f64);
    println!("  Exact predictions when selector collides: {exact_predictions} / {selector_collisions} ({pred_rate:.6})");
    if pred_rate > 0.99 {
        println!("  [CONFIRMED] DDR differential is perfectly predictable when selector collides");
        println!("  This means 1/64 of all differential paths through DDR are 'free'");
    }
    println!();
}

// ───────────────────────── ATTACK 11 ────────────────────────────
// Intra-round re-keying window: between re-keyings (every 8 rounds),
// the permutation structure is fixed. Test how 7 consecutive rounds
// WITHOUT re-keying compare to 7 rounds WITH re-keying.

fn attack_11_rekey_window() {
    println!("=== ATTACK 11: Intra-Round Re-Keying Window Analysis ===");
    let mut rng = Rng::new(0xDEAD_BEEF_1234_5678);
    let trials = 50_000;

    // Run 7 rounds (no re-keying triggers at rounds 0-6)
    // vs 8 rounds (re-keying at round 7)
    // Does the re-keying at round 8 measurably improve diffusion?

    for (label, round_count) in [("7 (no rekey)", 7), ("8 (with rekey at 7)", 8), ("9 (post-rekey)", 9)] {
        let mut total_h = 0u64;
        let mut min_h = u32::MAX;

        for _ in 0..trials {
            let state = rng.random_state();
            let mut s1 = state;
            let mut s2 = state;
            s2[0] ^= 1; // single bit flip

            kk_permute_n(&mut s1, &DEFAULT_ROTATIONS, round_count);
            kk_permute_n(&mut s2, &DEFAULT_ROTATIONS, round_count);

            let h = state_hamming(&s1, &s2);
            total_h += h as u64;
            min_h = min_h.min(h);
        }

        let avg = total_h as f64 / trials as f64;
        println!("  Rounds={label}: avg_hamming={avg:.1}/1600  min={min_h}");
    }
    println!();
}

// ─────────────────────── MAIN ───────────────────────────────────

fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       KK CRYPTANALYSIS: ADVERSARIAL SELF-ATTACK         ║");
    println!("║  Attempting to find weaknesses in the KK permutation    ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let start = Instant::now();

    attack_1_ddr_collision();
    attack_2_reduced_round_differential();
    attack_3_capacity_isolation();
    attack_4_sac();
    attack_5_mfr_bias();
    attack_6_round_constant_coverage();
    attack_7_row4_capacity_mixing();
    attack_8_kdf_squeeze_gap();
    attack_9_quintet_differential();
    attack_10_ddr_differential();
    attack_11_rekey_window();

    let elapsed = start.elapsed();
    println!("═══════════════════════════════════════════════════════════");
    println!("  Total analysis time: {:.2}s", elapsed.as_secs_f64());
    println!("═══════════════════════════════════════════════════════════");
}
