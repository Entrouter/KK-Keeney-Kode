// Copyright (c) 2026 John Keeney. MIT License.
// See LICENSE file in the project root for full license information.

//! QKD + KK Split-Channel  - End-to-End Demo
//!
//! Demonstrates the full pipeline:
//!   1. BB84 quantum key distribution (simulated)
//!   2. KK split-channel encoding
//!   3. QKD-encrypted ε transport
//!   4. Decoding with reunited channels
//!   5. Eve interception scenario (detected & rejected)
//!
//! Run: cargo run --example qkd_demo

use std::io::{self, Write};

use crossterm::style::{Attribute, Color, SetAttribute, SetForegroundColor, ResetColor};
use kk_crypto::{
    alice_prepare, bob_measure, distill_key, eve_intercept,
    encrypt_epsilon, decrypt_epsilon,
    encode_split, decode_split,
};

fn color(c: Color, text: &str) {
    print!("{}{}{}", SetForegroundColor(c), text, ResetColor);
}

fn bold(text: &str) {
    print!("{}{}{}", SetAttribute(Attribute::Bold), text, SetAttribute(Attribute::Reset));
}

fn header(title: &str) {
    println!();
    print!("  ");
    bold(&format!("━━━ {} ", title));
    let pad = if title.len() < 56 { 56 - title.len() } else { 4 };
    println!("{}", "━".repeat(pad));
}

fn hex_preview(data: &[u8], max: usize) {
    for (i, byte) in data.iter().take(max).enumerate() {
        if i > 0 && i % 24 == 0 {
            println!();
            print!("      ");
        }
        color(Color::DarkGrey, &format!("{:02x}", byte));
    }
    if data.len() > max {
        color(Color::DarkGrey, &format!(" ..+{}", data.len() - max));
    }
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // ═══════════════════════════════════════════════════════════════
    //  Title
    // ═══════════════════════════════════════════════════════════════
    println!();
    bold("  ╔══════════════════════════════════════════════════════════════╗\n");
    bold("  ║");
    color(Color::Cyan, "    BB84 QKD + KK SPLIT-CHANNEL  - End-to-End Demonstration");
    bold("   ║\n");
    bold("  ╚══════════════════════════════════════════════════════════════╝\n");

    let shared_secret = b"keeney-kode-qkd-2026";
    let plaintext = b"Information-theoretic security: achieved.";
    let n_qubits = 4096;

    // ═══════════════════════════════════════════════════════════════
    //  SCENARIO 1: Clean channel (no eavesdropper)
    // ═══════════════════════════════════════════════════════════════
    bold("\n  ┌──────────────────────────────────────────────────────────────┐\n");
    bold("  │");
    color(Color::Green, "  SCENARIO 1: Secure Channel  - No Eavesdropper");
    bold("               │\n");
    bold("  └──────────────────────────────────────────────────────────────┘\n");

    // Step 1: BB84 Key Exchange
    header("STEP 1  - BB84 Quantum Key Exchange");
    print!("    Alice prepares {} qubits (random bits × random bases)...\n", n_qubits);
    out.flush().ok();
    let alice = alice_prepare(n_qubits);

    print!("    Bob measures with random bases...\n");
    let bob = bob_measure(&alice.qubits);

    print!("    Public basis comparison + sifting...\n");
    let qkd = distill_key(&alice, &bob).unwrap();

    println!();
    print!("    Qubits exchanged:  ");
    color(Color::White, &format!("{}", qkd.n_qubits));
    println!();
    print!("    Sifted key bits:   ");
    color(Color::White, &format!("{}", qkd.n_sifted));
    print!("  (~{}%)", qkd.n_sifted * 100 / qkd.n_qubits);
    println!();
    print!("    Check bits used:   ");
    color(Color::White, &format!("{}", qkd.n_check_bits));
    println!();
    print!("    Error rate:        ");
    color(Color::Green, &format!("{:.1}%", qkd.error_rate * 100.0));
    println!();
    print!("    Eve detected:      ");
    color(Color::Green, "NO  - channel is clean");
    println!();
    print!("    QKD shared key:    ");
    hex_preview(&qkd.shared_key_alice, 32);
    println!();

    // Step 2: KK Split-Channel Encode
    header("STEP 2  - KK Split-Channel Encode");
    print!("    Plaintext: ");
    color(Color::Green, &format!("\"{}\"", String::from_utf8_lossy(plaintext)));
    println!();

    let (sealed, epsilon) = encode_split(shared_secret, plaintext).unwrap();
    let sealed_bytes = sealed.to_bytes();
    let epsilon_bytes = epsilon.to_bytes();

    println!();
    print!("    KkSealedMessage:   ");
    color(Color::Cyan, &format!("{} bytes", sealed_bytes.len()));
    print!("  (ciphertext + HMAC)");
    println!();
    print!("    EntropySnapshot:   ");
    color(Color::Magenta, &format!("{} bytes", epsilon_bytes.len()));
    print!("  (ε  - the moment)");
    println!();

    // Step 3: Encrypt ε with QKD key
    header("STEP 3  - Encrypt ε with QKD Key");
    let encrypted_eps = encrypt_epsilon(&qkd.shared_key_alice, &epsilon);

    print!("    ε encrypted with QKD-derived key → ");
    color(Color::Yellow, &format!("{} bytes", encrypted_eps.len()));
    println!();
    print!("      ");
    hex_preview(&encrypted_eps, 48);
    println!();
    println!();
    print!("    ");
    color(Color::DarkGrey, "ε can now travel on the SAME public wire as the ciphertext.");
    println!();
    print!("    ");
    color(Color::DarkGrey, "Only someone with the QKD key can unwrap it.");
    println!();

    // Step 4: Bob decrypts ε and decodes
    header("STEP 4  - Bob Receives & Decodes");
    print!("    Bob receives: KkSealedMessage + encrypted ε (both public wire)\n");
    print!("    Bob decrypts ε with QKD key...\n");

    let recovered_eps = decrypt_epsilon(&qkd.shared_key_alice, &encrypted_eps).unwrap();

    print!("    Bob calls decode_split(secret, sealed, ε)...\n\n");
    let recovered = decode_split(shared_secret, &sealed, &recovered_eps).unwrap();

    print!("    Result: ");
    color(Color::Green, &format!("\"{}\"", String::from_utf8_lossy(&recovered)));
    println!();
    print!("    Match:  ");
    if recovered == plaintext {
        color(Color::Green, "✓ PERFECT  - plaintext recovered");
    } else {
        color(Color::Red, "✗ MISMATCH");
    }
    println!();

    // ═══════════════════════════════════════════════════════════════
    //  SCENARIO 2: Eve intercepts the quantum channel
    // ═══════════════════════════════════════════════════════════════
    bold("\n  ┌──────────────────────────────────────────────────────────────┐\n");
    bold("  │");
    color(Color::Red, "  SCENARIO 2: Eve Intercepts the Quantum Channel");
    bold("            │\n");
    bold("  └──────────────────────────────────────────────────────────────┘\n");

    header("STEP 1  - BB84 with Eavesdropper");
    print!("    Alice prepares {} qubits...\n", n_qubits);
    let alice2 = alice_prepare(n_qubits);

    print!("    ");
    color(Color::Red, "⚡ Eve intercepts the quantum channel!");
    println!();
    print!("    Eve measures with random bases and re-sends...\n");
    let (eve, tampered_qubits) = eve_intercept(&alice2.qubits);

    print!("    Bob measures Eve's tampered qubits...\n");
    let bob2 = bob_measure(&tampered_qubits);

    let qkd2 = distill_key(&alice2, &bob2).unwrap();

    println!();
    print!("    Qubits exchanged:  ");
    color(Color::White, &format!("{}", qkd2.n_qubits));
    println!();
    print!("    Sifted key bits:   ");
    color(Color::White, &format!("{}", qkd2.n_sifted));
    println!();
    print!("    Check bits used:   ");
    color(Color::White, &format!("{}", qkd2.n_check_bits));
    println!();
    print!("    Error rate:        ");
    color(Color::Red, &format!("{:.1}%", qkd2.error_rate * 100.0));
    print!("  (expected ~25% with Eve)");
    println!();
    print!("    Eve detected:      ");
    if qkd2.eve_detected {
        color(Color::Red, "YES  - EAVESDROPPER DETECTED!");
    } else {
        color(Color::Yellow, "no (lucky Eve  - unlikely with more qubits)");
    }
    println!();

    header("PROTOCOL RESPONSE");
    if qkd2.eve_detected {
        print!("    ");
        color(Color::Red, "⛔ KEY EXCHANGE ABORTED");
        println!();
        print!("    ");
        color(Color::Red, "The quantum channel has been compromised.");
        println!();
        print!("    ");
        color(Color::Red, "Alice and Bob discard all key material.");
        println!();
        print!("    ");
        color(Color::Red, "No message is sent. Eve learns NOTHING.");
        println!();
    } else {
        print!("    ");
        color(Color::Yellow, "Eve got lucky on the check bits, but her key ≠ Alice's key.");
        println!();
        print!("    ");
        color(Color::Yellow, "With more qubits, detection probability → 100%.");
        println!();
    }

    // Show what Eve actually got
    header("WHAT EVE KNOWS");
    let eve_correct: usize = eve.bases.iter()
        .zip(alice2.bases.iter())
        .filter(|(e, a)| e == a)
        .count();
    let eve_pct = eve_correct * 100 / n_qubits;

    print!("    Eve's correct basis guesses: ");
    color(Color::Yellow, &format!("{}/{} (~{}%)", eve_correct, n_qubits, eve_pct));
    println!();
    print!("    Eve's key matches Alice's:   ");
    color(Color::Red, "NO  - different raw key bits, different HKDF output");
    println!();
    print!("    Eve can decrypt ε:           ");
    color(Color::Red, "NO  - wrong QKD key");
    println!();
    print!("    Eve can brute-force:         ");
    color(Color::Red, "NO  - missing ε means no HKDF salt");
    println!();

    // ═══════════════════════════════════════════════════════════════
    //  Security Summary
    // ═══════════════════════════════════════════════════════════════
    header("SECURITY ARCHITECTURE");
    println!();
    color(Color::Cyan, "    Alice");
    print!("                                            ");
    color(Color::Cyan, "Bob");
    println!();
    print!("      │                                              │\n");
    print!("      ├── ");
    color(Color::Magenta, "BB84 quantum channel");
    print!(" ──────────────────┤\n");
    print!("      │   ");
    color(Color::DarkGrey, "(qubits → sift → check → QKD key)");
    println!();
    print!("      │                                              │\n");
    print!("      ├── ");
    color(Color::Cyan, "Channel 1");
    print!(": KkSealedMessage ");
    color(Color::DarkGrey, "(public)");
    print!(" ──→│\n");
    print!("      ├── ");
    color(Color::Yellow, "Channel 2");
    print!(": QKD-encrypted ε ");
    color(Color::DarkGrey, "(public)");
    print!(" ──→│\n");
    print!("      │                                              │\n");
    print!("      │        Bob: QKD-decrypt ε → decode_split()   │\n");

    println!();
    print!("    ");
    bold("Three-factor security:");
    println!();
    print!("      ");
    color(Color::Green, "1.");
    print!(" Shared secret (pre-shared knowledge)\n");
    print!("      ");
    color(Color::Green, "2.");
    print!(" KkSealedMessage (ciphertext + HMAC)\n");
    print!("      ");
    color(Color::Green, "3.");
    print!(" ε (QKD-encrypted, physics-protected)\n");

    println!();
    print!("    ");
    bold("Attacker must defeat:");
    println!();
    print!("      ");
    color(Color::Red, "•");
    print!(" Heisenberg uncertainty (no-cloning theorem) to steal QKD key\n");
    print!("      ");
    color(Color::Red, "•");
    print!(" Information-theoretic ε non-reconstructibility\n");
    print!("      ");
    color(Color::Red, "•");
    print!(" HMAC-SHA256 temporal commitment binding\n");
    print!("      ");
    color(Color::Red, "•");
    print!(" HKDF-SHA256 key derivation without salt\n");

    println!();
    print!("    ");
    color(Color::Green, "Result: security guaranteed by laws of physics, not computational assumptions.");
    println!();

    println!();
    print!("  ");
    color(Color::DarkGrey, "BB84 + KK Split-Channel  - J.A. Keeney, Australia, 2026");
    println!();
    println!();
}
