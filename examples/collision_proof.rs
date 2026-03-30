// COLLISION PROOF: Tests whether flipping word 6 bit 0 produces a hash collision.
//
// Background: MFR uses `b | 1` to guarantee an odd (bijective) multiplier,
// which masks bit 0 of the b-argument. Word 6 occupies the b-position in
// the row and column phases. Without countermeasures, this could create
// an invariant differential.
//
// Mitigations:
//   1. MFR re-injects raw `b` via `product ^ (product >> 32) ^ b`,
//      so all 64 bits of b (including bit 0) influence the output.
//   2. The diagonal quintet ordering is rotated: DIAGS[0] = [24, 0, 6, 12, 18],
//      so word 6 is at the c-position (not b) in the diagonal phase.
//
// Result: NO COLLISION — hashes differ completely. The `⊕ b` countermeasure
// and diagonal rotation close this structural concern.
use kk_crypto::kk_mix::kk_hash;

fn main() {
    // Build two 304-byte messages (2 full rate blocks of 152 bytes each)
    let mut m1 = vec![0u8; 304];
    // Fill with non-trivial data
    let mut rng = 0xCAFE_BABE_DEAD_BEEFu64;
    for b in m1.iter_mut() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        *b = rng as u8;
    }

    // M2: flip byte 48 bit 0 in BOTH blocks
    // Block 1 spans bytes [0..152), byte 48 is word 6 of block 1
    // Block 2 spans bytes [152..304), byte 48+152 = 200 is word 6 of block 2
    let mut m2 = m1.clone();
    m2[48] ^= 0x01; // flip bit 0 of word 6, block 1
    m2[152 + 48] ^= 0x01; // flip bit 0 of word 6, block 2

    // Messages are distinct
    assert_ne!(m1, m2, "messages must differ");
    assert_ne!(m1[48], m2[48]);
    assert_ne!(m1[200], m2[200]);

    let h1 = kk_hash(&m1);
    let h2 = kk_hash(&m2);

    println!("M1[48]  = 0x{:02X},  M2[48]  = 0x{:02X}", m1[48], m2[48]);
    println!("M1[200] = 0x{:02X},  M2[200] = 0x{:02X}", m1[200], m2[200]);
    println!();
    println!("H(M1) = {}", hex(&h1));
    println!("H(M2) = {}", hex(&h2));
    println!();

    if h1 == h2 {
        println!("[COLLISION CONFIRMED] Two distinct 304-byte messages produce identical kk_hash.");
        println!("This is a zero-cost, universal collision for any 2+ block message.");
        println!();
        println!("Root cause: word 6 is in the b-position of ALL quintet phases.");
        println!("  Row 1:     [5, *6*, 7, 8, 9]    -> b");
        println!("  Column 1:  [1, *6*, 11, 16, 21]  -> b");
        println!("  Diagonal 0:[0, *6*, 12, 18, 24]  -> b");
        println!("  MFR(a, b, rot) uses (b | 1), so bit 0 of b is always masked.");
        println!("  => Differential at word 6 bit 0 is an INVARIANT of the permutation.");
    } else {
        println!("[NO COLLISION] hashes differ. Finding not confirmed.");
        // Print XOR to see the difference
        let xor: Vec<u8> = h1.iter().zip(h2.iter()).map(|(a, b)| a ^ b).collect();
        println!("H1 ^ H2 = {}", hex(&xor));
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
