# KK-Crypto Integration Guide

This guide shows how to integrate KK-Crypto into your Rust project.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
kk-crypto = { path = "../KK-Keeney-Kode" }
```

For `no_std` environments (exposes only `kk_mix` core):

```toml
[dependencies]
kk-crypto = { path = "../KK-Keeney-Kode", default-features = false }
```

## Basic Encode / Decode

```rust
use kk_crypto::{encode, decode};

let secret = b"shared-secret-between-parties";
let plaintext = b"Hello, KK!";

// Encode  - entropy is captured automatically
let packet = encode(secret, plaintext).unwrap();

// Transmit packet.to_bytes() over the wire...

// Decode
let recovered = decode(secret, &packet).unwrap();
assert_eq!(recovered, plaintext);
```

Every call to `encode` produces a unique ciphertext, even for the same plaintext and key.

## AEAD Mode (Authenticated Encryption with Associated Data)

```rust
use kk_crypto::{encode_aead, decode_aead};

let secret = b"shared-secret";
let plaintext = b"sensitive payload";
let aad = b"metadata-not-encrypted-but-authenticated";

let packet = encode_aead(secret, plaintext, aad).unwrap();

// Receiver must supply the same AAD
let recovered = decode_aead(secret, &packet, aad).unwrap();
assert_eq!(recovered, plaintext);

// Wrong AAD → rejection
assert!(decode_aead(secret, &packet, b"wrong-aad").is_err());
```

## Streaming API

For large messages, use `StreamEncoder` / `StreamDecoder` to process data incrementally:

```rust
use kk_crypto::{StreamEncoder, StreamDecoder};

let secret = b"shared-secret";
let data = b"large message split across multiple buffers";

// Encode in chunks
let mut encoder = StreamEncoder::new(secret);
encoder.update(&data[..20]);
encoder.update(&data[20..]);
let packet = encoder.finalize().unwrap();

// Decode in chunks
let mut decoder = StreamDecoder::new(
    secret,
    packet.snapshot.clone(),
    packet.temporal_commitment.clone(),
);
decoder.update(&packet.ciphertext[..16]);
decoder.update(&packet.ciphertext[16..]);
let recovered = decoder.finalize().unwrap();
assert_eq!(recovered, data);
```

## Session Mode (Forward Secrecy)

The Rope Ratchet provides ~192-bit forward secrecy via 4-strand ratcheting:

```rust
use kk_crypto::{encode_session, decode_session, RopeRatchet};

let secret = b"initial-shared-secret";

let mut alice = RopeRatchet::new(secret);
let mut bob = RopeRatchet::new(secret);

// Alice sends
let msg = b"forward-secret message";
let (packet, step) = encode_session(&mut alice, msg).unwrap();

// Bob receives
let recovered = decode_session(&mut bob, &packet, &step).unwrap();
assert_eq!(recovered, msg);
```

## EKA (Entropy Key Agreement)

Establish a shared secret without a pre-shared key, using a three-message handshake:

```rust
use kk_crypto::eka::{EkaInitiator, EkaResponder};

// Initiator starts
let mut initiator = EkaInitiator::new();
let msg1 = initiator.message_1();

// Responder processes msg1, produces msg2
let mut responder = EkaResponder::new();
let msg2 = responder.message_2(&msg1);

// Initiator processes msg2, produces msg3
let msg3 = initiator.message_3(&msg2).unwrap();

// Responder finishes
responder.message_3_received(&msg3).unwrap();

// Both sides now share the same key
assert_eq!(initiator.shared_secret(), responder.shared_secret());
```

## Using `kk_mix` Core in no_std

With `default-features = false`, only the `kk_mix` module is available. This gives you the raw KK primitives without any OS dependencies:

```rust
use kk_crypto::kk_mix::{kk_hash, kk_kdf, kk_mac, kk_mac_verify};

// Hash
let digest: [u8; 32] = kk_hash(b"data");

// KDF  - derive 64 bytes
let derived: Vec<u8> = kk_kdf(b"key", b"salt", b"context", 64);

// MAC
let tag: [u8; 32] = kk_mac(b"key", b"message");
assert!(kk_mac_verify(b"key", b"message", &tag));
```

## Error Handling

All fallible operations return `Result<T, KkError>`. Key error variants:

| Variant | Meaning |
|---------|---------|
| `InvalidPacket(msg)` | Corrupt or truncated packet |
| `MacMismatch` | Authentication tag verification failed |
| `TemporalMismatch` | Temporal commitment does not match |
| `EntropyFailure(msg)` | Entropy source unavailable |
| `EmptyInput` | Zero-length plaintext supplied |
