//! BB84 Quantum Key Distribution  - Simulated Protocol
//!
//! This module implements the BB84 protocol (Bennett & Brassard, 1984)
//! as a classical simulation. In real QKD, polarised photons carry the
//! quantum states; here we simulate the quantum behaviour faithfully:
//!
//! - Measuring in the **correct** basis always gives the right bit.
//! - Measuring in the **wrong** basis gives a random coin flip (50/50).
//! - An eavesdropper (Eve) who intercepts and re-sends introduces
//!   detectable errors (~25% on the sifted key).
//!
//! ## Protocol Steps
//!
//! ```text
//! 1. Alice → prepares N qubits: random bits × random bases
//! 2. Alice → sends qubits over quantum channel → Bob
//! 3. Bob   → measures each qubit in a random basis
//! 4. Public: Alice & Bob announce bases (NOT bits)
//! 5. Sifting: keep only positions where bases matched
//! 6. Error estimation: sacrifice a subset, compare bits
//! 7. Privacy amplification: KK-KDF on raw key → final key
//! ```
//!
//! ## Simulation vs Real Hardware
//!
//! This is a faithful **simulation** using OS-level CSPRNG (`OsRng`)
//! for quantum randomness. A real deployment would replace `OsRng`
//! with actual photon-source hardware. The protocol logic, sifting,
//! error estimation, and privacy amplification are identical either way.
//!
//! ## Integration with KK Split-Channel
//!
//! The QKD-derived key encrypts the `EntropySnapshot` (ε) for secure
//! delivery over the public channel. Combined with `KkSealedMessage`,
//! this gives end-to-end information-theoretic security (in principle).
//!
//! ```text
//! Alice                                          Bob
//!   │                                              │
//!   ├── BB84 quantum channel ──────────────────────┤
//!   │   (qubits → sifting → error check → key)    │
//!   │                                              │
//!   ├── Channel 1 (public): KkSealedMessage ──────→│
//!   ├── Channel 2 (QKD-encrypted ε) ──────────────→│
//!   │                                              │
//!   │   Bob: QKD-decrypt ε, then decode_split()   │
//! ```
//!
//! J.A. Keeney, Australia, 2026

use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroize;

use crate::entropy::EntropySnapshot;
use crate::error::{KkError, Result};
use crate::kk_mix;

// ─────────────────────────────────────────────────────────────────
//  Quantum primitives (simulated)
// ─────────────────────────────────────────────────────────────────

/// Measurement basis for a qubit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// Rectilinear basis (+): 0 = |, 1 =  -
    Rectilinear,
    /// Diagonal basis (×): 0 = ╲, 1 = ╱
    Diagonal,
}

/// A simulated qubit: a bit encoded in a particular basis.
///
/// In real QKD, this would be a polarised photon. The key property:
/// measuring in the wrong basis destroys the information and gives
/// a uniformly random result.
#[derive(Debug, Clone)]
pub struct Qubit {
    /// The actual bit Alice encoded
    bit: bool,
    /// The basis Alice used to encode it
    basis: Basis,
}

impl Qubit {
    /// Measure this qubit in the given basis.
    ///
    /// - **Correct basis:** returns the true bit (deterministic).
    /// - **Wrong basis:** returns a random bit (quantum uncertainty).
    ///
    /// After measurement, the qubit collapses  - the original state
    /// is destroyed. This is what makes eavesdropping detectable.
    pub fn measure(&self, measurement_basis: Basis) -> bool {
        if measurement_basis == self.basis {
            // Correct basis → deterministic result
            self.bit
        } else {
            // Wrong basis → quantum coin flip (OS-level CSPRNG)
            OsRng.gen_bool(0.5)
        }
    }
}

// ─────────────────────────────────────────────────────────────────
//  BB84 Protocol Roles
// ─────────────────────────────────────────────────────────────────

/// Alice's state during the BB84 protocol.
pub struct Alice {
    /// The random bits Alice chose
    pub bits: Vec<bool>,
    /// The random bases Alice used to encode
    pub bases: Vec<Basis>,
    /// The qubits Alice sends over the quantum channel
    pub qubits: Vec<Qubit>,
}

/// Bob's state after measuring received qubits.
pub struct Bob {
    /// The random bases Bob chose for measurement
    pub bases: Vec<Basis>,
    /// The measurement results
    pub measured_bits: Vec<bool>,
}

/// Result of the BB84 key exchange.
pub struct Bb84Result {
    /// The sifted key (only positions where bases matched)
    pub sifted_key_alice: Vec<bool>,
    pub sifted_key_bob: Vec<bool>,
    /// Number of raw qubits exchanged
    pub n_qubits: usize,
    /// Number of bits after sifting
    pub n_sifted: usize,
    /// Number of bits sacrificed for error estimation
    pub n_check_bits: usize,
    /// Detected error rate on check bits (0.0 = no eavesdropper)
    pub error_rate: f64,
    /// Whether Eve was detected (error_rate > threshold)
    pub eve_detected: bool,
    /// Alice's final key after privacy amplification (32 bytes)
    pub shared_key_alice: [u8; 32],
    /// Bob's final key after privacy amplification (32 bytes)
    /// In a clean channel (no Eve), this equals shared_key_alice.
    pub shared_key_bob: [u8; 32],
}

/// An eavesdropper who intercepts qubits on the quantum channel.
pub struct Eve {
    /// The bases Eve uses to measure (random  - she doesn't know Alice's)
    pub bases: Vec<Basis>,
    /// What Eve measured
    pub measured_bits: Vec<bool>,
}

// ─────────────────────────────────────────────────────────────────
//  Protocol Implementation
// ─────────────────────────────────────────────────────────────────

/// Default number of qubits to exchange.
/// More qubits → longer sifted key → more check bits → better security.
pub const DEFAULT_N_QUBITS: usize = 4096;

/// Error rate threshold above which we declare eavesdropper detected.
/// BB84 theory: Eve introduces ~25% errors on sifted key.
/// We use 10% as a conservative threshold.
const EVE_DETECTION_THRESHOLD: f64 = 0.10;

/// Fraction of sifted bits sacrificed for error estimation.
const CHECK_FRACTION: f64 = 0.25;

/// Step 1: Alice prepares qubits.
pub fn alice_prepare(n: usize) -> Alice {
    let mut rng = OsRng;
    let mut bits = Vec::with_capacity(n);
    let mut bases = Vec::with_capacity(n);
    let mut qubits = Vec::with_capacity(n);

    for _ in 0..n {
        let bit = rng.gen_bool(0.5);
        let basis = if rng.gen_bool(0.5) {
            Basis::Rectilinear
        } else {
            Basis::Diagonal
        };
        qubits.push(Qubit { bit, basis });
        bits.push(bit);
        bases.push(basis);
    }

    Alice {
        bits,
        bases,
        qubits,
    }
}

/// Step 2 (optional): Eve intercepts qubits on the quantum channel.
///
/// Eve measures each qubit in a random basis, then re-sends a new qubit
/// encoded with her measurement result. This disturbs qubits where she
/// guessed the wrong basis, introducing detectable errors.
pub fn eve_intercept(qubits: &[Qubit]) -> (Eve, Vec<Qubit>) {
    let mut rng = OsRng;
    let mut bases = Vec::with_capacity(qubits.len());
    let mut measured_bits = Vec::with_capacity(qubits.len());
    let mut resent = Vec::with_capacity(qubits.len());

    for qubit in qubits {
        let eve_basis = if rng.gen_bool(0.5) {
            Basis::Rectilinear
        } else {
            Basis::Diagonal
        };
        // Eve measures  - collapses the quantum state
        let eve_bit = qubit.measure(eve_basis);
        // Eve re-sends in her own basis (she doesn't know Alice's)
        resent.push(Qubit {
            bit: eve_bit,
            basis: eve_basis,
        });
        bases.push(eve_basis);
        measured_bits.push(eve_bit);
    }

    (
        Eve {
            bases,
            measured_bits,
        },
        resent,
    )
}

/// Step 3: Bob measures received qubits in random bases.
pub fn bob_measure(qubits: &[Qubit]) -> Bob {
    let mut rng = OsRng;
    let mut bases = Vec::with_capacity(qubits.len());
    let mut measured_bits = Vec::with_capacity(qubits.len());

    for qubit in qubits {
        let basis = if rng.gen_bool(0.5) {
            Basis::Rectilinear
        } else {
            Basis::Diagonal
        };
        measured_bits.push(qubit.measure(basis));
        bases.push(basis);
    }

    Bob {
        bases,
        measured_bits,
    }
}

/// Steps 4-7: Sifting, error estimation, and privacy amplification.
///
/// Returns the full BB84 result including the final shared key.
pub fn distill_key(alice: &Alice, bob: &Bob) -> Result<Bb84Result> {
    let n = alice.bits.len();

    // Step 4-5: Sifting  - keep only matching bases
    let mut sifted_alice = Vec::new();
    let mut sifted_bob = Vec::new();

    for i in 0..n {
        if alice.bases[i] == bob.bases[i] {
            sifted_alice.push(alice.bits[i]);
            sifted_bob.push(bob.measured_bits[i]);
        }
    }

    let n_sifted = sifted_alice.len();
    if n_sifted < 64 {
        return Err(KkError::EntropyFailure(
            "BB84: too few sifted bits for secure key".into(),
        ));
    }

    // Step 6: Error estimation  - sacrifice some bits
    let n_check = (n_sifted as f64 * CHECK_FRACTION) as usize;
    let n_check = n_check.max(16); // minimum 16 check bits

    let mut errors = 0;
    for i in 0..n_check {
        if sifted_alice[i] != sifted_bob[i] {
            errors += 1;
        }
    }
    let error_rate = errors as f64 / n_check as f64;
    let eve_detected = error_rate > EVE_DETECTION_THRESHOLD;

    // Remaining bits form the raw key
    let raw_alice: Vec<bool> = sifted_alice[n_check..].to_vec();
    let raw_bob: Vec<bool> = sifted_bob[n_check..].to_vec();

    // Step 7: Privacy amplification  - hash raw key bits into final key
    let key_bytes_alice = bits_to_bytes(&raw_alice);
    let key_bytes_bob = bits_to_bytes(&raw_bob);

    let mut shared_key_alice = [0u8; 32];
    let mut shared_key_bob = [0u8; 32];

    // Use KK-KDF to amplify privacy and produce a clean 256-bit key
    let derived_a = kk_mix::kk_kdf(&key_bytes_alice, b"BB84-KK-v1", b"KK-QKD-shared-key", 32);
    shared_key_alice.copy_from_slice(&derived_a);

    let derived_b = kk_mix::kk_kdf(&key_bytes_bob, b"BB84-KK-v1", b"KK-QKD-shared-key", 32);
    shared_key_bob.copy_from_slice(&derived_b);

    Ok(Bb84Result {
        sifted_key_alice: sifted_alice,
        sifted_key_bob: sifted_bob,
        n_qubits: n,
        n_sifted,
        n_check_bits: n_check,
        error_rate,
        eve_detected,
        shared_key_alice,
        shared_key_bob,
    })
}

// ─────────────────────────────────────────────────────────────────
//  QKD-secured ε transport
// ─────────────────────────────────────────────────────────────────

/// Encrypt an `EntropySnapshot` (ε) using the QKD-derived key.
///
/// This replaces the "private channel" assumption with a
/// physics-guaranteed key. The encrypted ε can now travel
/// over the same public wire as the ciphertext.
///
/// Uses XOR with KK-KDF-expanded key material (same primitive as KK).
pub fn encrypt_epsilon(qkd_key: &[u8; 32], epsilon: &EntropySnapshot) -> Vec<u8> {
    let epsilon_bytes = epsilon.to_bytes();

    // Derive keystream from QKD key
    let mut keystream = kk_mix::kk_kdf(b"QKD-epsilon-transport", qkd_key, b"KK-QKD-epsilon-v1", epsilon_bytes.len());

    // XOR encrypt
    let encrypted: Vec<u8> = epsilon_bytes
        .iter()
        .zip(keystream.iter())
        .map(|(e, k)| e ^ k)
        .collect();

    keystream.zeroize();
    encrypted
}

/// Decrypt an `EntropySnapshot` (ε) using the QKD-derived key.
pub fn decrypt_epsilon(qkd_key: &[u8; 32], encrypted: &[u8]) -> Result<EntropySnapshot> {
    let mut keystream = kk_mix::kk_kdf(b"QKD-epsilon-transport", qkd_key, b"KK-QKD-epsilon-v1", encrypted.len());

    let decrypted: Vec<u8> = encrypted
        .iter()
        .zip(keystream.iter())
        .map(|(e, k)| e ^ k)
        .collect();

    keystream.zeroize();
    EntropySnapshot::from_bytes(&decrypted)
}

// ─────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────

/// Pack a bit vector into bytes (MSB first, zero-padded).
fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let n_bytes = bits.len().div_ceil(8);
    let mut bytes = vec![0u8; n_bytes];
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            bytes[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    bytes
}

// ─────────────────────────────────────────────────────────────────
//  Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy;

    #[test]
    fn bb84_no_eve_clean_key() {
        // Without eavesdropper, Alice and Bob should agree
        let alice = alice_prepare(DEFAULT_N_QUBITS);
        let bob = bob_measure(&alice.qubits);
        let result = distill_key(&alice, &bob).unwrap();

        // ~50% of qubits survive sifting
        assert!(result.n_sifted > 1500, "expected ~2048 sifted bits, got {}", result.n_sifted);

        // Error rate should be 0% (no Eve)
        assert_eq!(result.error_rate, 0.0, "no Eve means zero errors");
        assert!(!result.eve_detected);

        // Key should be non-zero
        assert_ne!(result.shared_key_alice, [0u8; 32]);

        // Without Eve, Alice and Bob derive the same key
        assert_eq!(result.shared_key_alice, result.shared_key_bob);
    }

    #[test]
    fn bb84_eve_detected() {
        // With eavesdropper, error rate should be ~25%
        let alice = alice_prepare(DEFAULT_N_QUBITS);

        // Eve intercepts
        let (_eve, tampered_qubits) = eve_intercept(&alice.qubits);

        // Bob measures Eve's tampered qubits
        let bob = bob_measure(&tampered_qubits);
        let result = distill_key(&alice, &bob).unwrap();

        // Error rate should be ~25% (±some variance)
        assert!(
            result.error_rate > 0.15,
            "Eve should cause >15% errors, got {:.1}%",
            result.error_rate * 100.0
        );
        assert!(result.eve_detected, "Eve should be detected");
    }

    #[test]
    fn epsilon_encrypt_decrypt_roundtrip() {
        let qkd_key = [42u8; 32];
        let epsilon = entropy::gather().unwrap();

        let encrypted = encrypt_epsilon(&qkd_key, &epsilon);
        let decrypted = decrypt_epsilon(&qkd_key, &encrypted).unwrap();

        assert_eq!(epsilon.bytes, decrypted.bytes);
        assert_eq!(epsilon.timestamp_nanos, decrypted.timestamp_nanos);
    }

    #[test]
    fn wrong_qkd_key_corrupts_epsilon() {
        let real_key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let epsilon = entropy::gather().unwrap();

        let encrypted = encrypt_epsilon(&real_key, &epsilon);
        let decrypted = decrypt_epsilon(&wrong_key, &encrypted).unwrap();

        // Wrong key → wrong ε → will fail HMAC verification during decode_split
        assert_ne!(epsilon.bytes, decrypted.bytes);
    }

    #[test]
    fn qubit_correct_basis_deterministic() {
        // Correct basis always returns the real bit
        for bit in [true, false] {
            for basis in [Basis::Rectilinear, Basis::Diagonal] {
                let q = Qubit { bit, basis };
                for _ in 0..100 {
                    assert_eq!(q.measure(basis), bit);
                }
            }
        }
    }

    #[test]
    fn qubit_wrong_basis_random() {
        // Wrong basis should give ~50% distribution
        let q = Qubit {
            bit: true,
            basis: Basis::Rectilinear,
        };
        let trials = 1000;
        let trues: usize = (0..trials)
            .filter(|_| q.measure(Basis::Diagonal))
            .count();

        // Should be roughly 500 ± some margin
        assert!(
            trues > 350 && trues < 650,
            "wrong basis should be ~50/50, got {trues}/{trials}"
        );
    }

    #[test]
    fn full_qkd_kk_integration() {
        // End-to-end: BB84 → encrypt ε → split-channel encode → decrypt ε → decode
        use crate::codec::{encode_split, decode_split};

        let shared_secret = b"integration-test-secret";
        let plaintext = b"QKD + KK = information-theoretic security";

        // 1. BB84 key exchange (no Eve)
        let alice = alice_prepare(DEFAULT_N_QUBITS);
        let bob_state = bob_measure(&alice.qubits);
        let qkd = distill_key(&alice, &bob_state).unwrap();
        assert!(!qkd.eve_detected);

        // 2. Alice encodes with split-channel
        let (sealed, epsilon) = encode_split(shared_secret, plaintext).unwrap();

        // 3. Alice encrypts ε with QKD key, sends over public wire
        let encrypted_epsilon = encrypt_epsilon(&qkd.shared_key_alice, &epsilon);

        // 4. Bob decrypts ε with same QKD key
        let recovered_epsilon = decrypt_epsilon(&qkd.shared_key_alice, &encrypted_epsilon).unwrap();

        // 5. Bob decodes the message
        let recovered = decode_split(shared_secret, &sealed, &recovered_epsilon).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
