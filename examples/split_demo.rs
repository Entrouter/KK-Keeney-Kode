// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! Split-Channel KK Demo
//!
//! Demonstrates the two-channel architecture where ciphertext and ε
//! travel on separate paths. An attacker intercepting only the public
//! channel sees noise with no way to derive keys.
//!
//! Run: cargo run --example split_demo

use std::io::{self, Write};

use crossterm::style::{Attribute, Color, SetAttribute, SetForegroundColor, ResetColor};
use kk_crypto::{encode_split, decode_split};

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
    println!("{}", "━".repeat(60 - title.len()));
}

fn hex_dump(data: &[u8], max: usize) {
    for (i, byte) in data.iter().take(max).enumerate() {
        if i > 0 && i % 32 == 0 {
            println!();
            print!("    ");
        }
        color(Color::DarkGrey, &format!("{:02x}", byte));
    }
    if data.len() > max {
        color(Color::DarkGrey, &format!(" ... +{} bytes", data.len() - max));
    }
    println!();
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    println!();
    bold("  ╔══════════════════════════════════════════════════════════╗\n");
    bold("  ║");
    color(Color::Cyan, "        KK SPLIT-CHANNEL DEMO, Two Paths, One Truth");
    bold("      ║\n");
    bold("  ╚══════════════════════════════════════════════════════════╝\n");

    let shared_secret = b"demo-shared-secret-2026";
    let plaintext = b"The KK primitive makes each symbol a function of the universe.";

    // ─── Step 1: Show the plaintext ───
    header("PLAINTEXT");
    print!("    ");
    color(Color::Green, &format!("\"{}\"", String::from_utf8_lossy(plaintext)));
    println!();
    print!("    ");
    color(Color::DarkGrey, &format!("{} bytes", plaintext.len()));
    println!();

    // ─── Step 2: Encode with split ───
    header("ENCODING (split-channel)");
    let (sealed, epsilon) = encode_split(shared_secret, plaintext).unwrap();
    let sealed_bytes = sealed.to_bytes();
    let epsilon_bytes = epsilon.to_bytes();

    print!("    ");
    color(Color::Yellow, "encode_split(secret, plaintext)");
    println!();
    print!("    → ");
    color(Color::Cyan, "KkSealedMessage");
    print!(" + ");
    color(Color::Magenta, "EntropySnapshot");
    println!();

    // ─── Step 3: Channel 1, Public wire ───
    header("CHANNEL 1, Public Wire (ciphertext + HMAC)");
    print!("    Type: ");
    color(Color::Cyan, "KkSealedMessage");
    println!();
    print!("    Size: ");
    color(Color::White, &format!("{} bytes", sealed_bytes.len()));
    print!(" (4-byte len + {} ciphertext + 32-byte HMAC)", sealed.ciphertext.len());
    println!();
    print!("    Data: ");
    println!();
    print!("    ");
    hex_dump(&sealed_bytes, 96);

    // ─── Step 4: Channel 2, Private path ───
    header("CHANNEL 2, Private Path (ε, the moment)");
    print!("    Type: ");
    color(Color::Magenta, "EntropySnapshot");
    println!();
    print!("    Size: ");
    color(Color::White, &format!("{} bytes", epsilon_bytes.len()));
    print!(" (32-byte mixed entropy + 16-byte timestamp)");
    println!();
    print!("    Data: ");
    println!();
    print!("    ");
    hex_dump(&epsilon_bytes, 48);

    // ─── Step 5: Attacker's view ───
    header("ATTACKER'S VIEW (Channel 1 only, no ε)");
    print!("    ");
    color(Color::Red, "✗ ");
    print!("Has ciphertext:  ");
    color(Color::DarkGrey, "yes");
    println!();
    print!("    ");
    color(Color::Red, "✗ ");
    print!("Has HMAC:        ");
    color(Color::DarkGrey, "yes");
    println!();
    print!("    ");
    color(Color::Red, "✗ ");
    print!("Has ε (salt):    ");
    color(Color::Red, "NO");
    println!();
    println!();
    print!("    ");
    color(Color::Red, "Without ε, the HKDF salt is missing.");
    println!();
    print!("    ");
    color(Color::Red, "Every passphrase guess produces a different salt-less");
    println!();
    print!("    ");
    color(Color::Red, "derivation, there is nothing to verify against.");
    println!();
    print!("    ");
    color(Color::Red, "Brute force is meaningless.");
    println!();

    // ─── Step 5b: Try decoding with wrong ε ───
    println!();
    print!("    Attempting decode with ");
    color(Color::Red, "wrong ε");
    print!("... ");
    out.flush().ok();

    // Gather a different entropy snapshot (different moment = different ε)
    let wrong_epsilon = kk_crypto::entropy::gather().unwrap();
    match decode_split(shared_secret, &sealed, &wrong_epsilon) {
        Err(e) => {
            color(Color::Red, &format!("REJECTED: {}", e));
            println!();
        }
        Ok(_) => {
            color(Color::Red, "unexpected success?!");
            println!();
        }
    }

    // ─── Step 6: Legitimate receiver ───
    header("LEGITIMATE RECEIVER (both channels reunited)");
    print!("    ");
    color(Color::Green, "✓ ");
    print!("Has ciphertext (Channel 1): ");
    color(Color::Cyan, &format!("{} bytes", sealed_bytes.len()));
    println!();
    print!("    ");
    color(Color::Green, "✓ ");
    print!("Has ε (Channel 2):          ");
    color(Color::Magenta, &format!("{} bytes", epsilon_bytes.len()));
    println!();
    print!("    ");
    color(Color::Green, "✓ ");
    print!("Has shared secret:          ");
    color(Color::Yellow, &format!("{} bytes", shared_secret.len()));
    println!();

    println!();
    print!("    Decoding... ");
    out.flush().ok();

    let recovered = decode_split(shared_secret, &sealed, &epsilon).unwrap();
    color(Color::Green, "SUCCESS");
    println!();
    println!();
    print!("    ");
    color(Color::Green, &format!("\"{}\"", String::from_utf8_lossy(&recovered)));
    println!();

    // ─── Step 7: Verification ───
    let matches = recovered == plaintext;
    println!();
    print!("    Plaintext match: ");
    if matches {
        color(Color::Green, "✓ IDENTICAL");
    } else {
        color(Color::Red, "✗ MISMATCH");
    }
    println!();

    // ─── Summary ───
    header("SECURITY SUMMARY");
    let items = [
        ("Channel 1 alone (ciphertext + HMAC)", Color::Red, "UNBREAKABLE, no salt for key derivation"),
        ("Channel 2 alone (ε)", Color::Red, "USELESS, just 48 bytes of entropy, no ciphertext"),
        ("Wrong ε + ciphertext", Color::Red, "REJECTED, HMAC verification fails"),
        ("Both channels + secret", Color::Green, "DECRYPTS, all three factors present"),
    ];

    for (label, c, desc) in &items {
        print!("    ");
        color(*c, if *c == Color::Green { "✓" } else { "✗" });
        print!(" {}: ", label);
        color(*c, desc);
        println!();
    }

    println!();
    print!("  ");
    color(Color::DarkGrey, "KK Split-Channel, J.A. Keeney, Australia, 2026");
    println!();
    println!();
}
