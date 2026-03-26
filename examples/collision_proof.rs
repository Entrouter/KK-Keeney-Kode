/// COLLISION PROOF: Demonstrates a zero-cost hash collision in kk_hash.
///
/// Root cause: word 6 (bytes 48-55) occupies the "b position" in ALL
/// three quintet phases (row 1, column 1, diagonal 0). The `b | 1`
/// masking in MFR makes bit 0 of the b-argument invisible. Therefore
/// the differential Δ = {word 6, bit 0} is a FIXED POINT of the
/// permutation: kk_permute(S ⊕ Δ) = kk_permute(S) ⊕ Δ for ALL S.
///
/// Attack: For any 2-block message M1||M2, flipping byte 48 bit 0 in
/// BOTH blocks cancels the differential after the second absorption,
/// producing identical internal state and thus identical hash output.

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
    m2[48] ^= 0x01;        // flip bit 0 of word 6, block 1
    m2[152 + 48] ^= 0x01;  // flip bit 0 of word 6, block 2

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
        let xor: Vec<u8> = h1.iter().zip(h2.iter()).map(|(a,b)| a^b).collect();
        println!("H1 ^ H2 = {}", hex(&xor));
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
