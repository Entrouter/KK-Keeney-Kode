// Targeted test: specifically flip bit 0 of "b-position" words
// to measure the worst-case capacity isolation rate
fn main() {
    // Inline the primitives (same as attack.rs)
    const DEFAULT_ROTATIONS: [[u32; 2]; 15] = [
        [7, 41],
        [13, 29],
        [19, 37],
        [23, 43],
        [3, 53],
        [11, 47],
        [17, 39],
        [5, 59],
        [31, 49],
        [9, 51],
        [15, 33],
        [21, 45],
        [27, 35],
        [1, 57],
        [25, 55],
    ];
    const DIAGS: [[usize; 5]; 5] = [
        [0, 6, 12, 18, 24],
        [1, 7, 13, 19, 20],
        [2, 8, 14, 15, 21],
        [3, 9, 10, 16, 22],
        [4, 5, 11, 17, 23],
    ];
    const DDR_MIX: u64 = 0xB5C0FBCFEC4D3B2F;
    #[inline(always)]
    fn mfr(a: u64, b: u64, rot: u32) -> u64 {
        let p = a.wrapping_mul(b | 1);
        (p ^ (p >> 32) ^ b).rotate_left(rot)
    }
    #[inline(always)]
    fn ddr(a: u64, b: u64) -> u64 {
        let s = (b.wrapping_mul(DDR_MIX)) >> 58;
        let mut v = a;
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
    #[inline(always)]
    fn qr(a: &mut u64, b: &mut u64, c: &mut u64, d: &mut u64, e: &mut u64, rot: [u32; 2]) {
        *a = mfr(*a, *b, rot[0]);
        *c ^= *a;
        *d = ddr(*d, *c);
        *e = mfr(*e, *d, rot[1]);
        *b ^= *e;
    }
    fn perm(state: &mut [u64; 25], rots: &[[u32; 2]; 15], rounds: usize) {
        for round in 0..rounds as u64 {
            for (row, rot) in rots.iter().enumerate().take(5) {
                let b = row * 5;
                let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                    state[b],
                    state[b + 1],
                    state[b + 2],
                    state[b + 3],
                    state[b + 4],
                );
                qr(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, *rot);
                state[b] = s0;
                state[b + 1] = s1;
                state[b + 2] = s2;
                state[b + 3] = s3;
                state[b + 4] = s4;
            }
            for col in 0..5usize {
                let (mut s0, mut s1, mut s2, mut s3, mut s4) = (
                    state[col],
                    state[col + 5],
                    state[col + 10],
                    state[col + 15],
                    state[col + 20],
                );
                qr(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rots[5 + col]);
                state[col] = s0;
                state[col + 5] = s1;
                state[col + 10] = s2;
                state[col + 15] = s3;
                state[col + 20] = s4;
            }
            for d in 0..5usize {
                let [i0, i1, i2, i3, i4] = DIAGS[d];
                let (mut s0, mut s1, mut s2, mut s3, mut s4) =
                    (state[i0], state[i1], state[i2], state[i3], state[i4]);
                qr(&mut s0, &mut s1, &mut s2, &mut s3, &mut s4, rots[10 + d]);
                state[i0] = s0;
                state[i1] = s1;
                state[i2] = s2;
                state[i3] = s3;
                state[i4] = s4;
            }
            state[0] = state[0].wrapping_add(round);
            state[4] = state[4].wrapping_add(round.wrapping_mul(0x9E3779B97F4A7C15));
            state[12] = state[12].wrapping_add(round.wrapping_mul(0xB7E151628AED2A6A));
            state[20] = state[20].wrapping_add(round.wrapping_mul(0x243F6A8885A2F7A4));
            state[24] = state[24].wrapping_add(round.wrapping_mul(0x298B075B4B6A5240));
            if round % 8 == 7 {
                for i in 0..19 {
                    state[i] ^= state[19 + (i % 6)].rotate_left(round as u32);
                }
            }
        }
    }
    struct Rng(u64);
    impl Rng {
        fn new(s: u64) -> Self {
            Self(s)
        }
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn state(&mut self) -> [u64; 25] {
            let mut s = [0u64; 25];
            for w in s.iter_mut() {
                *w = self.next();
            }
            s
        }
    }

    let mut rng = Rng::new(0xDEAD_CAFE_1234_5678);
    let trials = 500_000u64;

    // b-position rate words: word 1 (row 0), word 6 (row 1), word 11 (row 2), word 16 (row 3)
    let b_words = [1usize, 6, 11, 16];

    println!("=== TARGETED: bit-0 of b-position words, 32 rounds ===");
    for &tw in &b_words {
        let mut zero_cap = 0u64;
        let mut min_h = u32::MAX;
        let mut min_cap_h = u32::MAX;
        for _ in 0..trials {
            let s = rng.state();
            let mut s1 = s;
            let mut s2 = s;
            s2[tw] ^= 1; // flip bit 0
            perm(&mut s1, &DEFAULT_ROTATIONS, 32);
            perm(&mut s2, &DEFAULT_ROTATIONS, 32);
            let h: u32 = (0..25).map(|i| (s1[i] ^ s2[i]).count_ones()).sum();
            let ch: u32 = (19..25).map(|i| (s1[i] ^ s2[i]).count_ones()).sum();
            min_h = min_h.min(h);
            min_cap_h = min_cap_h.min(ch);
            if ch == 0 {
                zero_cap += 1;
            }
        }
        let rate = zero_cap as f64 / trials as f64;
        println!("  word {tw:2} bit 0: zero_cap={zero_cap}/{trials} ({rate:.4e})  min_total_h={min_h}  min_cap_h={min_cap_h}");
    }

    // Also test bit 0 of a-position words for comparison
    let a_words = [0usize, 5, 10, 15]; // position a in rows 0-3
    println!("\n=== CONTROL: bit-0 of a-position words, 32 rounds ===");
    for &tw in &a_words {
        let mut zero_cap = 0u64;
        let mut min_h = u32::MAX;
        for _ in 0..trials {
            let s = rng.state();
            let mut s1 = s;
            let mut s2 = s;
            s2[tw] ^= 1;
            perm(&mut s1, &DEFAULT_ROTATIONS, 32);
            perm(&mut s2, &DEFAULT_ROTATIONS, 32);
            let h: u32 = (0..25).map(|i| (s1[i] ^ s2[i]).count_ones()).sum();
            let ch: u32 = (19..25).map(|i| (s1[i] ^ s2[i]).count_ones()).sum();
            min_h = min_h.min(h);
            if ch == 0 {
                zero_cap += 1;
            }
        }
        let r = zero_cap as f64 / trials as f64;
        println!(
            "  word {tw:2} bit 0: zero_cap={zero_cap}/{trials} ({r:.4e})  min_total_h={min_h}"
        );
    }

    // Also test bit 1 of b-position words (NOT masked by |1)
    println!("\n=== COMPARISON: bit 1 of b-position words, 32 rounds ===");
    for &tw in &b_words {
        let mut zero_cap = 0u64;
        let mut min_h = u32::MAX;
        for _ in 0..trials {
            let s = rng.state();
            let mut s1 = s;
            let mut s2 = s;
            s2[tw] ^= 2; // flip bit 1 instead
            perm(&mut s1, &DEFAULT_ROTATIONS, 32);
            perm(&mut s2, &DEFAULT_ROTATIONS, 32);
            let h: u32 = (0..25).map(|i| (s1[i] ^ s2[i]).count_ones()).sum();
            let ch: u32 = (19..25).map(|i| (s1[i] ^ s2[i]).count_ones()).sum();
            min_h = min_h.min(h);
            if ch == 0 {
                zero_cap += 1;
            }
        }
        let r = zero_cap as f64 / trials as f64;
        println!(
            "  word {tw:2} bit 1: zero_cap={zero_cap}/{trials} ({r:.4e})  min_total_h={min_h}"
        );
    }
}
