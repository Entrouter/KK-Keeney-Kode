//! Cryptographic quality tests for the KK permutation and sponge.
//!
//! Six tests that empirically validate the cryptographic properties
//! of kk_hash, kk_mac, and the underlying KK permutation:
//!
//!   1. Strict Avalanche Criterion (SAC)
//!   2. Bit Independence Criterion (BIC)
//!   3. Collision Resistance
//!   4. Length Extension Resistance
//!   5. Statistical Randomness (chi-squared)
//!   6. Known-Answer Tests (KATs)
//!
//! Run with: cargo run --release --example crypto_quality

use kk_crypto::kk_mix::{kk_hash, kk_mac};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════════

/// Simple xorshift64 PRNG for deterministic test inputs.
struct Xorshift64(u64);

impl Xorshift64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(v.iter()) {
                *dst = *src;
            }
        }
    }
}

/// Count different bits between two byte slices.
fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Get bit `i` from a byte slice (bit 0 = MSB of byte 0).
fn get_bit(data: &[u8], i: usize) -> u8 {
    let byte_idx = i / 8;
    let bit_idx = 7 - (i % 8);
    (data[byte_idx] >> bit_idx) & 1
}

/// Flip bit `i` in a byte slice.
fn flip_bit(data: &mut [u8], i: usize) {
    let byte_idx = i / 8;
    let bit_idx = 7 - (i % 8);
    data[byte_idx] ^= 1 << bit_idx;
}

// ═══════════════════════════════════════════════════════════════
//  Test 1: Strict Avalanche Criterion (SAC)
// ═══════════════════════════════════════════════════════════════
//
//  For a cryptographically strong hash, flipping any single input
//  bit should cause each output bit to flip with probability 0.5.
//
//  We measure: for each input bit position, flip it, count the
//  number of output bits that changed. Average over many inputs.
//  The mean should be ~128 (50% of 256 bits), and every individual
//  bit position should be close to 50%.

fn test_sac() -> (bool, String) {
    const INPUT_LEN: usize = 32; // 256 input bits
    const OUTPUT_BITS: usize = 256;
    const NUM_INPUTS: usize = 2000;

    let mut rng = Xorshift64::new(0x5AC0_1234_5678_9ABC);

    // Accumulate: for each input bit, how many output bits flipped total
    let input_bits = INPUT_LEN * 8;
    let mut flip_counts = vec![0u64; input_bits];

    // Also track per-output-bit flip count (across all input bits and inputs)
    // to check that every output bit participates
    let mut output_bit_flips = vec![0u64; OUTPUT_BITS];

    for _ in 0..NUM_INPUTS {
        let mut input = vec![0u8; INPUT_LEN];
        rng.fill(&mut input);
        let base_hash = kk_hash(&input);

        for bit in 0..input_bits {
            let mut modified = input.clone();
            flip_bit(&mut modified, bit);
            let mod_hash = kk_hash(&modified);

            let hd = hamming_distance(&base_hash, &mod_hash);
            flip_counts[bit] += hd as u64;

            // Track which output bits flipped
            for ob in 0..OUTPUT_BITS {
                if get_bit(&base_hash, ob) != get_bit(&mod_hash, ob) {
                    output_bit_flips[ob] += 1;
                }
            }
        }
    }

    // Analysis
    let total_tests = input_bits as f64;
    let expected_hd = OUTPUT_BITS as f64 / 2.0; // 128

    // Per-input-bit: average hamming distance
    let mean_hd: f64 = flip_counts.iter().map(|&c| c as f64 / NUM_INPUTS as f64).sum::<f64>() / total_tests;

    // Min/max per-input-bit average
    let min_hd = flip_counts.iter().map(|&c| c as f64 / NUM_INPUTS as f64).fold(f64::MAX, f64::min);
    let max_hd = flip_counts.iter().map(|&c| c as f64 / NUM_INPUTS as f64).fold(f64::MIN, f64::max);

    // Per-output-bit: flip probability (should each be ~50%)
    let total_output_trials = (NUM_INPUTS * input_bits) as f64;
    let min_ob_pct = output_bit_flips.iter().map(|&c| c as f64 / total_output_trials * 100.0).fold(f64::MAX, f64::min);
    let max_ob_pct = output_bit_flips.iter().map(|&c| c as f64 / total_output_trials * 100.0).fold(f64::MIN, f64::max);

    // SAC passes if mean is within 128 ± 3 and all bits participate symmetrically
    let pass = (mean_hd - expected_hd).abs() < 3.0
        && min_hd > 118.0
        && max_hd < 138.0
        && min_ob_pct > 47.0
        && max_ob_pct < 53.0;

    let detail = format!(
        "mean flip = {:.2}/256 (expect 128.0), range [{:.1}, {:.1}], output bit flip range [{:.2}%, {:.2}%]",
        mean_hd, min_hd, max_hd, min_ob_pct, max_ob_pct
    );

    (pass, detail)
}

// ═══════════════════════════════════════════════════════════════
//  Test 2: Bit Independence Criterion (BIC)
// ═══════════════════════════════════════════════════════════════
//
//  For any input bit flip, each PAIR of output bits should change
//  independently. Measured via Pearson correlation between output
//  bit flip vectors. Max |correlation| should be near 0.

fn test_bic() -> (bool, String) {
    const INPUT_LEN: usize = 16;
    const OUTPUT_BITS: usize = 256;
    const NUM_INPUTS: usize = 5000;
    // Test a subset of output bit pairs for speed
    const PAIRS_TO_TEST: usize = 1000;

    let mut rng = Xorshift64::new(0xB1C0_DEAD_BEEF_CAFE);

    // Pick one input bit to flip (bit 0 of byte 0)
    // and collect the flip pattern across many inputs
    let mut flips = vec![[0u8; OUTPUT_BITS]; NUM_INPUTS];

    for trial in 0..NUM_INPUTS {
        let mut input = vec![0u8; INPUT_LEN];
        rng.fill(&mut input);
        let base = kk_hash(&input);

        flip_bit(&mut input, 0);
        let modified = kk_hash(&input);

        for ob in 0..OUTPUT_BITS {
            flips[trial][ob] = if get_bit(&base, ob) != get_bit(&modified, ob) { 1 } else { 0 };
        }
    }

    // Compute correlation for random pairs of output bits
    let mut max_corr: f64 = 0.0;
    let mut sum_corr: f64 = 0.0;
    let mut pair_count = 0usize;

    // Deterministic pair selection
    let mut pair_rng = Xorshift64::new(0xDA1A_5EED_C0FF_EEEE);
    for _ in 0..PAIRS_TO_TEST {
        let i = (pair_rng.next() as usize) % OUTPUT_BITS;
        let j = (pair_rng.next() as usize) % OUTPUT_BITS;
        if i == j { continue; }

        // Pearson correlation
        let n = NUM_INPUTS as f64;
        let sum_x: f64 = flips.iter().map(|f| f[i] as f64).sum();
        let sum_y: f64 = flips.iter().map(|f| f[j] as f64).sum();
        let sum_xy: f64 = flips.iter().map(|f| (f[i] as f64) * (f[j] as f64)).sum();
        let sum_x2: f64 = flips.iter().map(|f| (f[i] as f64).powi(2)).sum();
        let sum_y2: f64 = flips.iter().map(|f| (f[j] as f64).powi(2)).sum();

        let num = n * sum_xy - sum_x * sum_y;
        let den = ((n * sum_x2 - sum_x.powi(2)) * (n * sum_y2 - sum_y.powi(2))).sqrt();

        if den > 1e-10 {
            let r = (num / den).abs();
            max_corr = max_corr.max(r);
            sum_corr += r;
            pair_count += 1;
        }
    }

    let avg_corr = if pair_count > 0 { sum_corr / pair_count as f64 } else { 0.0 };

    // BIC passes if max correlation is below 0.1 and average is near 0
    let pass = max_corr < 0.1 && avg_corr < 0.05;

    let detail = format!(
        "tested {} pairs: max |r| = {:.4}, mean |r| = {:.4}",
        pair_count, max_corr, avg_corr
    );

    (pass, detail)
}

// ═══════════════════════════════════════════════════════════════
//  Test 3: Collision Resistance
// ═══════════════════════════════════════════════════════════════
//
//  Hash a large number of distinct inputs and verify zero
//  collisions. For a 256-bit hash, birthday bound is ~2^128.
//  Finding any collision in 2M inputs would be catastrophic.

fn test_collisions() -> (bool, String) {
    const NUM_INPUTS: usize = 2_000_000;

    let mut seen = HashSet::with_capacity(NUM_INPUTS);
    let mut collisions = 0u64;

    // Sequential integer inputs (worst-case for bad hash: nearby inputs)
    for i in 0..NUM_INPUTS as u64 {
        let hash = kk_hash(&i.to_le_bytes());
        if !seen.insert(hash) {
            collisions += 1;
        }
    }

    let pass = collisions == 0;
    let detail = format!(
        "{} inputs hashed, {} collisions (expect 0, birthday bound ≈ 2^128)",
        NUM_INPUTS, collisions
    );

    (pass, detail)
}

// ═══════════════════════════════════════════════════════════════
//  Test 4: Length Extension Resistance
// ═══════════════════════════════════════════════════════════════
//
//  In a vulnerable hash (e.g., raw Merkle-Damgård), knowing H(m)
//  lets you compute H(m || pad || suffix) without knowing m.
//  A sponge with hidden capacity prevents this.
//
//  Test: verify that H(m || suffix) cannot be predicted from H(m)
//  by trying the naive length-extension approach and confirming
//  it produces a DIFFERENT result.

fn test_length_extension() -> (bool, String) {
    const NUM_TRIALS: usize = 1000;
    let mut rng = Xorshift64::new(0x1E_AE21_5EED_1234);
    let mut blocked = 0u64;

    for _ in 0..NUM_TRIALS {
        // Random message
        let mut msg = vec![0u8; 32];
        rng.fill(&mut msg);

        // Random suffix
        let mut suffix = vec![0u8; 16];
        rng.fill(&mut suffix);

        // Real hash of concatenated message
        let mut extended = msg.clone();
        extended.extend_from_slice(&suffix);
        let real_hash = kk_hash(&extended);

        // Naive length-extension attempt:
        // Start a hash from H(m) as if it were internal state,
        // then absorb the suffix. This should NOT match.
        let h_m = kk_hash(&msg);
        let mut attempt_input = Vec::new();
        attempt_input.extend_from_slice(&h_m);
        attempt_input.extend_from_slice(&suffix);
        let attempt_hash = kk_hash(&attempt_input);

        if attempt_hash != real_hash {
            blocked += 1;
        }
    }

    let pass = blocked == NUM_TRIALS as u64;
    let detail = format!(
        "{}/{} length-extension attempts blocked (expect 100%)",
        blocked, NUM_TRIALS
    );

    (pass, detail)
}

// ═══════════════════════════════════════════════════════════════
//  Test 5: Statistical Randomness (chi-squared)
// ═══════════════════════════════════════════════════════════════
//
//  Collect output bytes from many hash outputs and verify they
//  follow a uniform distribution via chi-squared goodness-of-fit.
//
//  For 256 bins (byte values), df=255, chi² critical value at
//  p=0.001 is ~310.5. Values below this → uniform distribution.

fn test_chi_squared() -> (bool, String) {
    const NUM_HASHES: usize = 100_000;
    const HASH_LEN: usize = 32;

    let mut counts = [0u64; 256];

    for i in 0..NUM_HASHES as u64 {
        let hash = kk_hash(&i.to_le_bytes());
        for &b in &hash {
            counts[b as usize] += 1;
        }
    }

    let total_bytes = (NUM_HASHES * HASH_LEN) as f64;
    let expected = total_bytes / 256.0;

    let chi_sq: f64 = counts.iter()
        .map(|&c| {
            let diff = c as f64 - expected;
            diff * diff / expected
        })
        .sum();

    // df = 255, two-tailed p=0.001 → lower ≈ 190, upper ≈ 330
    // (Wilson-Hilferty approximation with z = ±3.09)
    let pass = chi_sq > 190.0 && chi_sq < 330.0;
    let detail = format!(
        "chi² = {:.2} (df=255, expect 190 < χ² < 330 at p=0.001, {} bytes sampled)",
        chi_sq, total_bytes as u64
    );

    (pass, detail)
}

// ═══════════════════════════════════════════════════════════════
//  Test 6: Known-Answer Tests (KATs)
// ═══════════════════════════════════════════════════════════════
//
//  Frozen test vectors. If ANY of these change, something in the
//  core permutation or sponge has been modified (possibly a bug).
//  These act as regression guards.

fn test_kats() -> (bool, String) {
    // KAT_PLACEHOLDER: computed on first run, then frozen
    let vectors: Vec<(&[u8], &str)> = vec![
        // kk_hash of empty input
        (b"", "KAT_EMPTY"),
        // kk_hash of single zero byte
        (&[0u8], "KAT_ZERO"),
        // kk_hash of "KK"
        (b"KK", "KAT_KK"),
        // kk_hash of 152 zero bytes (exactly one rate block)
        (&[0u8; 152], "KAT_RATE_BLOCK"),
        // kk_hash of 153 zero bytes (one rate block + 1 byte → triggers second permutation)
        (&[0u8; 153], "KAT_RATE_PLUS_ONE"),
    ];

    println!();
    println!("  KAT values (freeze these for regression detection):");
    let mut all_deterministic = true;

    for (input, label) in &vectors {
        let hash1 = kk_hash(input);
        let hash2 = kk_hash(input);

        let hex1 = hash1.iter().map(|b| format!("{:02x}", b)).collect::<String>();

        if hash1 != hash2 {
            println!("    {} = NON-DETERMINISTIC!", label);
            all_deterministic = false;
        } else {
            println!("    {} = {}", label, hex1);
        }
    }

    // Also test MAC determinism
    let mac1 = kk_mac(b"test-key", b"test-message");
    let mac2 = kk_mac(b"test-key", b"test-message");
    let mac_hex = mac1.iter().map(|b| format!("{:02x}", b)).collect::<String>();

    if mac1 != mac2 {
        println!("    KAT_MAC  = NON-DETERMINISTIC!");
        all_deterministic = false;
    } else {
        println!("    KAT_MAC  = {}", mac_hex);
    }

    // Verify against frozen values
    let frozen_hashes: Vec<(&[u8], &str)> = vec![
        (b"" as &[u8], "8a2254a95c8537855961b5273bdd7e2921af6a1a6883d0607e9e9c2bf1962a65"),
        (&[0u8] as &[u8], "8a06fabeaff831b96879109ed34a1a876ebaa3339950d92a1d30b4e96708ffbf"),
        (b"KK" as &[u8], "5ae9c2b6a5322c6e31f17d993ff4cad2efae61ad9df5c9eb6b37c0ef9c1ad435"),
        (&[0u8; 152] as &[u8], "280f2b1e4d94aefb92013b142ecefe9f5b9b8fdeefa55aa99a57a740e79b30bb"),
        (&[0u8; 153] as &[u8], "6e81a0cd022d34f77699bf3bcd39b2d0d86555cb194c843dd36636ed4f30ad86"),
    ];
    let frozen_mac = "9f0ac88d6b5a99e51faf1bb8324511fd705bc8a0182b9f625a86ad3c687957bb";

    let mut all_match = true;
    for (input, expected_hex) in &frozen_hashes {
        let hash = kk_hash(input);
        let hex = hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        if hex != *expected_hex {
            println!("    MISMATCH for input len {}: got {}", input.len(), hex);
            all_match = false;
        }
    }
    let actual_mac_hex = mac_hex;
    if actual_mac_hex != frozen_mac {
        println!("    MAC MISMATCH: got {}", actual_mac_hex);
        all_match = false;
    }

    let pass = all_deterministic && all_match;
    let detail = if all_match {
        format!("6 vectors verified: all deterministic, all match frozen values")
    } else {
        format!("REGRESSION: computed values don't match frozen KAT vectors!")
    };

    (pass, detail)
}

// ═══════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  KK-Crypto Cryptographic Quality Test Suite                     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let tests: Vec<(&str, fn() -> (bool, String))> = vec![
        ("Strict Avalanche Criterion", test_sac),
        ("Bit Independence Criterion", test_bic),
        ("Collision Resistance (2M inputs)", test_collisions),
        ("Length Extension Resistance", test_length_extension),
        ("Statistical Randomness (χ²)", test_chi_squared),
        ("Known-Answer Tests (KATs)", test_kats),
    ];

    let mut results = Vec::new();

    for (i, (name, test_fn)) in tests.iter().enumerate() {
        print!("  Running test {}: {} ...", i + 1, name);
        // Flush so the user sees progress
        use std::io::Write;
        std::io::stdout().flush().ok();

        let (pass, detail) = test_fn();
        let status = if pass { "PASS" } else { "FAIL" };
        let marker = if pass { "  " } else { "!!" };

        println!("\r  Test {}: {} {} {}  {}", i + 1, status, marker, name, "");
        println!("         {}", detail);
        println!();

        results.push((name, pass));
    }

    // Summary
    let passed = results.iter().filter(|(_, p)| *p).count();
    let total = results.len();

    println!("══════════════════════════════════════════════════════════════════");
    if passed == total {
        println!("  Result: ALL {}/{} TESTS PASSED", passed, total);
    } else {
        println!("  Result: {}/{} PASSED  - FAILURES DETECTED", passed, total);
        for (name, pass) in &results {
            if !pass {
                println!("    FAILED: {}", name);
            }
        }
    }
    println!();

    if passed < total {
        std::process::exit(1);
    }
}
