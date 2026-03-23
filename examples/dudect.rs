// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Dudect-style timing leak detection for KK-Crypto.
//!
//! Implements the methodology from "Dude, is my code constant time?"
//! (Reparaz, Balasch, Verbauwhede, 2017).
//!
//! For each function under test, we:
//!   1. Prepare two classes of inputs: "fixed" (class 0) and "random" (class 1)
//!   2. Randomly interleave measurements of both classes
//!   3. Compute Welch's t-test on the timing distributions
//!   4. If |t| > THRESHOLD after sufficient samples, timing leak detected
//!
//! Run with: cargo run --release --example dudect
//! (MUST be --release to avoid debug-mode noise masking real signals)

use std::time::Instant;

use kk_crypto::kk_mix::{kk_hash, kk_mac, kk_mac_verify};

/// Welch's t-test threshold. The original dudect paper uses 4.5.
/// Values above this indicate statistically significant timing differences.
const THRESHOLD: f64 = 4.5;

/// Number of measurements per class.
const SAMPLES: usize = 100_000;

/// Online Welch's t-test accumulator.
/// Computes t-statistic incrementally without storing all samples.
struct WelchT {
    n0: f64,
    n1: f64,
    mean0: f64,
    mean1: f64,
    m2_0: f64,
    m2_1: f64,
}

impl WelchT {
    fn new() -> Self {
        Self {
            n0: 0.0,
            n1: 0.0,
            mean0: 0.0,
            mean1: 0.0,
            m2_0: 0.0,
            m2_1: 0.0,
        }
    }

    /// Push a timing measurement into the appropriate class.
    /// Uses Welford's online algorithm for numerical stability.
    fn push(&mut self, class: u8, value: f64) {
        if class == 0 {
            self.n0 += 1.0;
            let delta = value - self.mean0;
            self.mean0 += delta / self.n0;
            let delta2 = value - self.mean0;
            self.m2_0 += delta * delta2;
        } else {
            self.n1 += 1.0;
            let delta = value - self.mean1;
            self.mean1 += delta / self.n1;
            let delta2 = value - self.mean1;
            self.m2_1 += delta * delta2;
        }
    }

    /// Compute Welch's t-statistic.
    /// Returns None if insufficient samples.
    fn t_statistic(&self) -> Option<f64> {
        if self.n0 < 2.0 || self.n1 < 2.0 {
            return None;
        }
        let var0 = self.m2_0 / (self.n0 - 1.0);
        let var1 = self.m2_1 / (self.n1 - 1.0);
        let denom = (var0 / self.n0 + var1 / self.n1).sqrt();
        if denom < 1e-15 {
            return None;
        }
        Some((self.mean0 - self.mean1) / denom)
    }
}

/// Simple xorshift64 PRNG, deterministic, fast, no system calls.
/// We don't need cryptographic randomness for the test harness.
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

    fn next_byte(&mut self) -> u8 {
        self.next() as u8
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_byte();
        }
    }
}

/// Measure the execution time of a closure in nanoseconds.
/// Uses a tight loop with Instant for sub-microsecond resolution.
#[inline(never)]
fn measure_ns<F: FnMut()>(mut f: F) -> f64 {
    let start = Instant::now();
    f();
    start.elapsed().as_nanos() as f64
}

/// Cropping: discard measurements above the percentile threshold
/// to remove OS scheduling noise. Returns threshold value.
fn percentile(times: &mut [f64], pct: f64) -> f64 {
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((times.len() as f64) * pct) as usize;
    times[idx.min(times.len() - 1)]
}

// ─────────────────────────────────────────────────────────────
//  Test 1: constant_time_eq via kk_mac_verify
//  Class 0: verify with the CORRECT tag (should return true)
//  Class 1: verify with a WRONG tag (should return false)
//  If constant-time: both classes take the same time.
// ─────────────────────────────────────────────────────────────

fn test_mac_verify_ct() -> (f64, &'static str) {
    let key = b"dudect-test-key-0123456789abcdef";
    let message = b"the quick brown fox jumps over the lazy dog";
    let correct_tag = kk_mac(key, message);

    // Wrong tag: flip every byte
    let mut wrong_tag = correct_tag;
    for b in wrong_tag.iter_mut() {
        *b ^= 0xFF;
    }

    let mut rng = Xorshift64::new(0xDEAD_BEEF_CAFE_BABE);
    let mut tester = WelchT::new();

    // Pre-allocate class assignments and shuffle
    let mut classes = vec![0u8; SAMPLES * 2];
    for i in 0..SAMPLES {
        classes[i * 2] = 0;
        classes[i * 2 + 1] = 1;
    }
    // Fisher-Yates shuffle
    for i in (1..classes.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        classes.swap(i, j);
    }

    // Collect raw timings first (phase 1)
    let mut timings: Vec<(u8, f64)> = Vec::with_capacity(classes.len());
    for &class in &classes {
        let t = if class == 0 {
            measure_ns(|| { let _ = kk_mac_verify(key, message, &correct_tag); })
        } else {
            measure_ns(|| { let _ = kk_mac_verify(key, message, &wrong_tag); })
        };
        timings.push((class, t));
    }

    // Crop outliers (top 5%, OS noise)
    let mut all_times: Vec<f64> = timings.iter().map(|(_, t)| *t).collect();
    let crop_threshold = percentile(&mut all_times, 0.95);

    // Feed into t-test, skipping outliers
    for &(class, t) in &timings {
        if t <= crop_threshold {
            tester.push(class, t);
        }
    }

    let t = tester.t_statistic().unwrap_or(0.0);
    (t, "kk_mac_verify (correct vs wrong tag)")
}

// ─────────────────────────────────────────────────────────────
//  Test 2: MAC computation timing doesn't depend on key value
//  Class 0: MAC with a fixed all-zero key
//  Class 1: MAC with a random key
//  If constant-time: both classes take the same time.
// ─────────────────────────────────────────────────────────────

fn test_mac_key_independence() -> (f64, &'static str) {
    let fixed_key = [0u8; 32];
    let message = b"the quick brown fox jumps over the lazy dog";

    let mut rng = Xorshift64::new(0x1234_5678_9ABC_DEF0);

    let mut classes = vec![0u8; SAMPLES * 2];
    for i in 0..SAMPLES {
        classes[i * 2] = 0;
        classes[i * 2 + 1] = 1;
    }
    for i in (1..classes.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        classes.swap(i, j);
    }

    // Pre-generate random keys for class 1
    let mut random_keys: Vec<[u8; 32]> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut k = [0u8; 32];
        rng.fill(&mut k);
        random_keys.push(k);
    }

    let mut tester = WelchT::new();
    let mut rand_idx = 0usize;
    let mut timings: Vec<(u8, f64)> = Vec::with_capacity(classes.len());

    for &class in &classes {
        let t = if class == 0 {
            measure_ns(|| { let _ = kk_mac(&fixed_key, message); })
        } else {
            let k = &random_keys[rand_idx % random_keys.len()];
            rand_idx += 1;
            measure_ns(|| { let _ = kk_mac(k, message); })
        };
        timings.push((class, t));
    }

    let mut all_times: Vec<f64> = timings.iter().map(|(_, t)| *t).collect();
    let crop_threshold = percentile(&mut all_times, 0.95);

    for &(class, t) in &timings {
        if t <= crop_threshold {
            tester.push(class, t);
        }
    }

    let t = tester.t_statistic().unwrap_or(0.0);
    (t, "kk_mac (fixed vs random key)")
}

// ─────────────────────────────────────────────────────────────
//  Test 3: MAC computation timing doesn't depend on message
//  Class 0: MAC with all-zero message
//  Class 1: MAC with all-0xFF message
//  Same length, only content varies.
// ─────────────────────────────────────────────────────────────

fn test_mac_message_independence() -> (f64, &'static str) {
    let key = b"dudect-test-key-0123456789abcdef";
    let msg_zero = [0u8; 64];
    let msg_ones = [0xFFu8; 64];

    let mut rng = Xorshift64::new(0xAAAA_BBBB_CCCC_DDDD);

    let mut classes = vec![0u8; SAMPLES * 2];
    for i in 0..SAMPLES {
        classes[i * 2] = 0;
        classes[i * 2 + 1] = 1;
    }
    for i in (1..classes.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        classes.swap(i, j);
    }

    let mut tester = WelchT::new();
    let mut timings: Vec<(u8, f64)> = Vec::with_capacity(classes.len());

    for &class in &classes {
        let t = if class == 0 {
            measure_ns(|| { let _ = kk_mac(key, &msg_zero); })
        } else {
            measure_ns(|| { let _ = kk_mac(key, &msg_ones); })
        };
        timings.push((class, t));
    }

    let mut all_times: Vec<f64> = timings.iter().map(|(_, t)| *t).collect();
    let crop_threshold = percentile(&mut all_times, 0.95);

    for &(class, t) in &timings {
        if t <= crop_threshold {
            tester.push(class, t);
        }
    }

    let t = tester.t_statistic().unwrap_or(0.0);
    (t, "kk_mac (zero vs 0xFF message)")
}

// ─────────────────────────────────────────────────────────────
//  Test 4: kk_mac_verify with near-miss tags
//  Class 0: tag differs in FIRST byte only
//  Class 1: tag differs in LAST byte only
//  If comparison short-circuits, class 0 would be faster.
// ─────────────────────────────────────────────────────────────

fn test_mac_verify_position() -> (f64, &'static str) {
    let key = b"dudect-test-key-0123456789abcdef";
    let message = b"the quick brown fox jumps over the lazy dog";
    let correct_tag = kk_mac(key, message);

    // Differ in first byte
    let mut wrong_first = correct_tag;
    wrong_first[0] ^= 1;

    // Differ in last byte
    let mut wrong_last = correct_tag;
    wrong_last[31] ^= 1;

    let mut rng = Xorshift64::new(0xFEED_FACE_DEAD_C0DE);

    let mut classes = vec![0u8; SAMPLES * 2];
    for i in 0..SAMPLES {
        classes[i * 2] = 0;
        classes[i * 2 + 1] = 1;
    }
    for i in (1..classes.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        classes.swap(i, j);
    }

    let mut tester = WelchT::new();
    let mut timings: Vec<(u8, f64)> = Vec::with_capacity(classes.len());

    for &class in &classes {
        let t = if class == 0 {
            measure_ns(|| { let _ = kk_mac_verify(key, message, &wrong_first); })
        } else {
            measure_ns(|| { let _ = kk_mac_verify(key, message, &wrong_last); })
        };
        timings.push((class, t));
    }

    let mut all_times: Vec<f64> = timings.iter().map(|(_, t)| *t).collect();
    let crop_threshold = percentile(&mut all_times, 0.95);

    for &(class, t) in &timings {
        if t <= crop_threshold {
            tester.push(class, t);
        }
    }

    let t = tester.t_statistic().unwrap_or(0.0);
    (t, "kk_mac_verify (first-byte vs last-byte wrong)")
}

// ─────────────────────────────────────────────────────────────
//  Test 5: Permutation timing doesn't depend on state content
//  Class 0: permute all-zero state
//  Class 1: permute all-0xFF state
//  The DDR paths should NOT vary in timing.
// ─────────────────────────────────────────────────────────────

fn test_permute_data_independence() -> (f64, &'static str) {
    // We test through kk_hash since kk_permute isn't directly
    // exposed, but same-length inputs go through identical absorb
    // patterns so timing differences come only from the permutation.
    let input_zero = [0u8; 152]; // exactly one rate block
    let input_ones = [0xFFu8; 152];

    let mut rng = Xorshift64::new(0x0BAD_F00D_1337_BEEF);

    let mut classes = vec![0u8; SAMPLES * 2];
    for i in 0..SAMPLES {
        classes[i * 2] = 0;
        classes[i * 2 + 1] = 1;
    }
    for i in (1..classes.len()).rev() {
        let j = (rng.next() as usize) % (i + 1);
        classes.swap(i, j);
    }

    let mut tester = WelchT::new();
    let mut timings: Vec<(u8, f64)> = Vec::with_capacity(classes.len());

    for &class in &classes {
        let t = if class == 0 {
            measure_ns(|| { let _ = kk_hash(&input_zero); })
        } else {
            measure_ns(|| { let _ = kk_hash(&input_ones); })
        };
        timings.push((class, t));
    }

    let mut all_times: Vec<f64> = timings.iter().map(|(_, t)| *t).collect();
    let crop_threshold = percentile(&mut all_times, 0.95);

    for &(class, t) in &timings {
        if t <= crop_threshold {
            tester.push(class, t);
        }
    }

    let t = tester.t_statistic().unwrap_or(0.0);
    (t, "kk_hash/permute (zero vs 0xFF state)")
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  KK-Crypto Constant-Time Verification (dudect methodology)     ║");
    println!("║  Samples per class: {:>7}                                     ║", SAMPLES);
    println!("║  Threshold: |t| < {:.1} → no timing leak detected              ║", THRESHOLD);
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    let tests: Vec<fn() -> (f64, &'static str)> = vec![
        test_mac_verify_ct,
        test_mac_key_independence,
        test_mac_message_independence,
        test_mac_verify_position,
        test_permute_data_independence,
    ];

    let mut all_pass = true;

    for (i, test_fn) in tests.iter().enumerate() {
        let (t, name) = test_fn();
        let abs_t = t.abs();
        let status = if abs_t < THRESHOLD { "PASS" } else { "FAIL" };
        let marker = if abs_t < THRESHOLD { "  " } else { "!!" };

        println!(
            "  Test {}: {} |t| = {:.2}  {}  {}",
            i + 1,
            status,
            abs_t,
            marker,
            name,
        );

        if abs_t >= THRESHOLD {
            all_pass = false;
        }
    }

    println!();
    if all_pass {
        println!("  Result: ALL TESTS PASSED, no timing leaks detected.");
        println!("  (with {} samples per class, threshold |t| < {:.1})", SAMPLES, THRESHOLD);
    } else {
        println!("  Result: TIMING LEAK DETECTED in one or more tests.");
        println!("  Functions marked !! may have data-dependent timing.");
    }
    println!();
    println!("  Note: dudect is statistical. Re-run to confirm any failures.");
    println!("  False positives are possible (~1/million at threshold 4.5).");
}
