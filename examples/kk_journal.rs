// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

//! KK Journal, An encrypted diary powered by the Keeney Kode.
//!
//! Every entry is encrypted at its unique entropic moment.
//! Without the passphrase AND the captured ε, the words are gone forever.
//!
//! Usage:
//!   cargo run --example kk-journal -- write          Write a new entry
//!   cargo run --example kk-journal -- list           List all entries
//!   cargo run --example kk-journal -- read <N>       Read entry N
//!   cargo run --example kk-journal -- read all       Read all entries
//!   cargo run --example kk-journal -- delete <N>     Delete entry N

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────
//  Config
// ─────────────────────────────────────────────────────────────────

fn journal_dir() -> PathBuf {
    // Store journal next to wherever you run it
    let dir = PathBuf::from("kk-journal");
    if !dir.exists() {
        fs::create_dir_all(&dir).expect("Failed to create journal directory");
    }
    dir
}

// ─────────────────────────────────────────────────────────────────
//  Entry metadata, stored in filename, no decryption needed to list
// ─────────────────────────────────────────────────────────────────

struct EntryMeta {
    timestamp_secs: u64,
    byte_size: u64,
    path: PathBuf,
}

fn list_entries() -> Vec<EntryMeta> {
    let dir = journal_dir();
    let mut entries: Vec<EntryMeta> = fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("Cannot read {}", dir.display()))
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map_or(false, |ext| ext == "kkj")
        })
        .filter_map(|e| {
            let ts_str = e.file_name().to_string_lossy().strip_suffix(".kkj")?.to_string();
            let timestamp_secs: u64 = ts_str.parse().ok()?;
            let byte_size = e.metadata().ok()?.len();
            Some(EntryMeta {
                timestamp_secs,
                byte_size,
                path: e.path(),
            })
        })
        .collect();

    entries.sort_by_key(|e| e.timestamp_secs);
    entries
}

// ─────────────────────────────────────────────────────────────────
//  Time formatting (no chrono dependency)
// ─────────────────────────────────────────────────────────────────

fn format_timestamp(epoch_secs: u64) -> String {
    // Simple breakdown, good enough for a journal
    let secs = epoch_secs;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since epoch to y/m/d (simplified Gregorian)
    let (year, month, day) = days_to_date(days);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─────────────────────────────────────────────────────────────────
//  Commands
// ─────────────────────────────────────────────────────────────────

fn cmd_write() {
    println!();
    println!("  ╔═══════════════════════════════════════════╗");
    println!("  ║  KK Journal, New Entry                   ║");
    println!("  ╚═══════════════════════════════════════════╝");
    println!();

    // Get passphrase
    let passphrase = prompt_passphrase("  Passphrase: ");
    if passphrase.is_empty() {
        eprintln!("  Passphrase cannot be empty.");
        std::process::exit(1);
    }

    // Confirm passphrase for new entries
    let confirm = prompt_passphrase("  Confirm:    ");
    if passphrase != confirm {
        eprintln!("  Passphrases don't match.");
        std::process::exit(1);
    }

    println!();
    println!("  Write your entry below. End with an empty line.");
    println!("  ────────────────────────────────────────────────");

    let mut lines: Vec<String> = Vec::new();

    loop {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf).expect("Failed to read line");
        let line = buf.trim_end_matches('\n').trim_end_matches('\r').to_string();
        if line.is_empty() && !lines.is_empty() {
            break;
        }
        if !line.is_empty() || !lines.is_empty() {
            lines.push(line);
        }
    }

    if lines.is_empty() {
        println!("  Empty entry, nothing saved.");
        return;
    }

    let entry_text = lines.join("\n");
    let plaintext = entry_text.as_bytes();

    // Encode with KK
    let packet = kk_crypto::encode(passphrase.as_bytes(), plaintext)
        .expect("Encoding failed");

    // Save
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let path = journal_dir().join(format!("{timestamp}.kkj"));
    let wire = packet.to_bytes();
    fs::write(&path, &wire).expect("Failed to write entry");

    println!();
    println!("  ✓ Entry saved, {} bytes encrypted", wire.len());
    println!("    Entropy ε: {}...", hex(&packet.entropy_snapshot.bytes[..8]));
    println!("    Timestamp: {}", format_timestamp(timestamp));
    println!("    That entropic moment is now gone. The entry is sealed.");
    println!();
}

fn cmd_list() {
    let entries = list_entries();

    println!();
    println!("  ╔═══════════════════════════════════════════╗");
    println!("  ║  KK Journal, Entries                     ║");
    println!("  ╚═══════════════════════════════════════════╝");
    println!();

    if entries.is_empty() {
        println!("  No entries yet. Use 'write' to create one.");
        println!();
        return;
    }

    println!(
        "  {:>4}  {:<24} {:>10}",
        "#", "Date", "Size"
    );
    println!("  ────  ────────────────────────  ──────────");

    for (i, entry) in entries.iter().enumerate() {
        println!(
            "  {:>4}  {:<24} {:>8} B",
            i + 1,
            format_timestamp(entry.timestamp_secs),
            entry.byte_size,
        );
    }

    println!();
    println!("  {} entries. Use 'read <N>' to decrypt.", entries.len());
    println!();
}

fn cmd_read(args: &[String]) {
    if args.len() < 3 {
        eprintln!("  Usage: kk-journal read <N|all>");
        std::process::exit(1);
    }

    let entries = list_entries();
    if entries.is_empty() {
        println!("  No entries to read.");
        return;
    }

    println!();

    // Get passphrase
    let passphrase = prompt_passphrase("  Passphrase: ");
    println!();

    if args[2] == "all" {
        for (i, entry) in entries.iter().enumerate() {
            read_single_entry(&passphrase, entry, i + 1);
        }
    } else {
        let n: usize = args[2].parse().unwrap_or_else(|_| {
            eprintln!("  Invalid entry number: {}", args[2]);
            std::process::exit(1);
        });
        if n == 0 || n > entries.len() {
            eprintln!(
                "  Entry #{n} doesn't exist. You have {} entries.",
                entries.len()
            );
            std::process::exit(1);
        }
        read_single_entry(&passphrase, &entries[n - 1], n);
    }
}

fn read_single_entry(passphrase: &str, entry: &EntryMeta, number: usize) {
    let wire = fs::read(&entry.path).expect("Failed to read entry file");
    let packet = match kk_crypto::KkPacket::from_bytes(&wire) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  Entry #{number}: corrupted packet, {e}");
            return;
        }
    };

    match kk_crypto::decode(passphrase.as_bytes(), &packet) {
        Ok(plaintext) => {
            let text = String::from_utf8_lossy(&plaintext);
            println!("  ┌─── Entry #{number}, {} ───", format_timestamp(entry.timestamp_secs));
            println!("  │");
            for line in text.lines() {
                println!("  │  {line}");
            }
            println!("  │");
            println!("  └─── ε: {}... ───", hex(&packet.entropy_snapshot.bytes[..8]));
            println!();
        }
        Err(_) => {
            println!("  ✗ Entry #{number}: wrong passphrase or tampered data.");
            println!("    The entropic moment rejects you.");
            println!();
        }
    }
}

fn cmd_delete(args: &[String]) {
    if args.len() < 3 {
        eprintln!("  Usage: kk-journal delete <N>");
        std::process::exit(1);
    }

    let entries = list_entries();
    let n: usize = args[2].parse().unwrap_or_else(|_| {
        eprintln!("  Invalid entry number: {}", args[2]);
        std::process::exit(1);
    });

    if n == 0 || n > entries.len() {
        eprintln!(
            "  Entry #{n} doesn't exist. You have {} entries.",
            entries.len()
        );
        std::process::exit(1);
    }

    let entry = &entries[n - 1];
    print!(
        "  Delete entry #{n} ({})? [y/N] ",
        format_timestamp(entry.timestamp_secs)
    );
    io::stdout().flush().unwrap();

    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap();

    if answer.trim().eq_ignore_ascii_case("y") {
        fs::remove_file(&entry.path).expect("Failed to delete entry");
        println!("  ✓ Entry #{n} deleted. Its entropic moment erased from disk.");
    } else {
        println!("  Cancelled.");
    }
    println!();
}

// ─────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────

fn prompt_passphrase(prompt: &str) -> String {
    print!("{prompt}");
    io::stdout().flush().unwrap();
    rpassword::read_password().expect("Failed to read passphrase")
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_usage() {
    println!();
    println!("  KK Journal, Encrypted diary powered by the Keeney Kode");
    println!();
    println!("  Usage:");
    println!("    kk-journal write          Write a new encrypted entry");
    println!("    kk-journal list           List all entries (no decryption)");
    println!("    kk-journal read <N>       Decrypt and read entry N");
    println!("    kk-journal read all       Decrypt and read all entries");
    println!("    kk-journal delete <N>     Delete entry N");
    println!();
    println!("  Each entry is sealed at its unique entropic moment.");
    println!("  Without your passphrase, the contents are gone forever.");
    println!();
}

// ─────────────────────────────────────────────────────────────────
//  Main
// ─────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "write" => cmd_write(),
        "list" => cmd_list(),
        "read" => cmd_read(&args),
        "delete" => cmd_delete(&args),
        "help" | "--help" | "-h" => print_usage(),
        other => {
            eprintln!("  Unknown command: {other}");
            print_usage();
            std::process::exit(1);
        }
    }
}
