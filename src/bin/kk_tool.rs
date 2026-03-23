// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! kk-tool: Command-line interface for KK cryptographic operations.
//!
//! Subcommands:
//!   hash   - KK-Hash of stdin or a string argument
//!   enc    - Encrypt a file with KK-AEAD
//!   dec    - Decrypt a file encrypted with KK-AEAD
//!   rand   - Generate pseudorandom bytes from a seed
//!   mac    - Compute KK-MAC of stdin or a string

use std::fs;
use std::io::{self, Read};

fn usage() {
    eprintln!("kk-tool - KK (Keeney Kode) cryptographic toolkit");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  kk-tool hash [TEXT]           Hash TEXT (or stdin) with KK-Hash");
    eprintln!("  kk-tool mac  KEY [TEXT]       MAC TEXT (or stdin) with KK-MAC");
    eprintln!("  kk-tool rand SEED LEN         Generate LEN random bytes from SEED");
    eprintln!("  kk-tool enc  KEY INPUT OUTPUT Encrypt file with KK-AEAD");
    eprintln!("  kk-tool dec  KEY INPUT OUTPUT Decrypt file with KK-AEAD");
    eprintln!();
    eprintln!("All output is hex-encoded. KEY is a passphrase string.");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_stdin() -> Vec<u8> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("failed to read stdin");
    buf
}

fn cmd_hash(args: &[String]) {
    let data = if args.is_empty() {
        read_stdin()
    } else {
        args[0].as_bytes().to_vec()
    };
    let digest = kk_crypto::kk_mix::kk_hash(&data);
    println!("{}", hex_encode(&digest));
}

fn cmd_mac(args: &[String]) {
    if args.is_empty() {
        eprintln!("Error: mac requires at least a KEY argument");
        std::process::exit(1);
    }
    let key = args[0].as_bytes();
    let data = if args.len() > 1 {
        args[1].as_bytes().to_vec()
    } else {
        read_stdin()
    };
    let tag = kk_crypto::kk_mix::kk_mac(key, &data);
    println!("{}", hex_encode(&tag));
}

fn cmd_rand(args: &[String]) {
    if args.len() < 2 {
        eprintln!("Error: rand requires SEED and LEN arguments");
        std::process::exit(1);
    }
    let seed = args[0].as_bytes();
    let len: usize = args[1].parse().unwrap_or_else(|_| {
        eprintln!("Error: LEN must be a positive integer");
        std::process::exit(1);
    });
    let mut rng = kk_crypto::rng::KkRng::new(seed);
    let bytes = rng.next_bytes(len);
    println!("{}", hex_encode(&bytes));
}

fn cmd_enc(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Error: enc requires KEY, INPUT, OUTPUT arguments");
        std::process::exit(1);
    }
    let key = args[0].as_bytes();
    let input_path = &args[1];
    let output_path = &args[2];

    let plaintext = fs::read(input_path).unwrap_or_else(|e| {
        eprintln!("Error reading {input_path}: {e}");
        std::process::exit(1);
    });

    let packet = kk_crypto::encode_aead(key, &plaintext, b"kk-tool").unwrap_or_else(|e| {
        eprintln!("Encryption failed: {e}");
        std::process::exit(1);
    });

    let wire = packet.to_bytes();
    fs::write(output_path, &wire).unwrap_or_else(|e| {
        eprintln!("Error writing {output_path}: {e}");
        std::process::exit(1);
    });

    eprintln!("Encrypted {} bytes → {} bytes written to {output_path}",
        plaintext.len(), wire.len());
}

fn cmd_dec(args: &[String]) {
    if args.len() < 3 {
        eprintln!("Error: dec requires KEY, INPUT, OUTPUT arguments");
        std::process::exit(1);
    }
    let key = args[0].as_bytes();
    let input_path = &args[1];
    let output_path = &args[2];

    let wire = fs::read(input_path).unwrap_or_else(|e| {
        eprintln!("Error reading {input_path}: {e}");
        std::process::exit(1);
    });

    let packet = kk_crypto::KkAeadPacket::from_bytes(&wire).unwrap_or_else(|e| {
        eprintln!("Invalid packet: {e}");
        std::process::exit(1);
    });

    let plaintext = kk_crypto::decode_aead(key, &packet).unwrap_or_else(|e| {
        eprintln!("Decryption failed: {e}");
        std::process::exit(1);
    });

    fs::write(output_path, &plaintext).unwrap_or_else(|e| {
        eprintln!("Error writing {output_path}: {e}");
        std::process::exit(1);
    });

    eprintln!("Decrypted {} bytes → {} bytes written to {output_path}",
        wire.len(), plaintext.len());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let cmd = args[1].as_str();
    let rest = &args[2..];

    match cmd {
        "hash" => cmd_hash(rest),
        "mac"  => cmd_mac(rest),
        "rand" => cmd_rand(rest),
        "enc"  => cmd_enc(rest),
        "dec"  => cmd_dec(rest),
        "-h" | "--help" | "help" => usage(),
        _ => {
            eprintln!("Unknown command: {cmd}");
            usage();
            std::process::exit(1);
        }
    }
}
