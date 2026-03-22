//! GPU correctness tests: verify GPU produces identical output to CPU.
//!
//! Run with: `cargo test --features gpu --test gpu_integration`

#![cfg(feature = "gpu")]

use kk_crypto::gpu::GpuAccelerator;
use kk_crypto::kk_mix::{
    kk_kdf, kk_permute_with_schedule, KkSponge, KkState, ROUNDS, STATE_WORDS,
};

/// Get the KK_IV by reading a fresh sponge's state.
fn kk_iv() -> KkState {
    KkSponge::new().state()
}

/// Helper: create a GpuAccelerator or skip the test if no GPU available.
fn gpu_or_skip() -> GpuAccelerator {
    match GpuAccelerator::new() {
        Ok(g) => {
            eprintln!("GPU test running on: {}", g.device_name());
            g
        }
        Err(e) => {
            eprintln!("Skipping GPU test (no GPU): {e}");
            std::process::exit(0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────
//  Permutation correctness
// ─────────────────────────────────────────────────────────────────

#[test]
fn gpu_permute_matches_cpu_iv_state() {
    let gpu = gpu_or_skip();
    let rotations = KkSponge::new().rotations();

    // Test with KK_IV as input
    let mut cpu_state = kk_iv();
    kk_permute_with_schedule(&mut cpu_state, &rotations);

    let mut gpu_states = vec![kk_iv()];
    gpu.permute_batch(&mut gpu_states, &rotations, ROUNDS);

    assert_eq!(
        cpu_state, gpu_states[0],
        "GPU permute of KK_IV must match CPU"
    );
}

#[test]
fn gpu_permute_matches_cpu_zero_state() {
    let gpu = gpu_or_skip();
    let rotations = KkSponge::new().rotations();

    let zero_state: KkState = [0u64; STATE_WORDS];

    let mut cpu_state = zero_state;
    kk_permute_with_schedule(&mut cpu_state, &rotations);

    let mut gpu_states = vec![zero_state];
    gpu.permute_batch(&mut gpu_states, &rotations, ROUNDS);

    assert_eq!(
        cpu_state, gpu_states[0],
        "GPU permute of zero state must match CPU"
    );
}

#[test]
fn gpu_permute_matches_cpu_patterned_state() {
    let gpu = gpu_or_skip();
    let rotations = KkSponge::new().rotations();

    // Deterministic non-trivial state
    let mut patterned: KkState = [0u64; STATE_WORDS];
    for i in 0..STATE_WORDS {
        patterned[i] = (i as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ 0xDEADBEEFCAFEBABE;
    }

    let mut cpu_state = patterned;
    kk_permute_with_schedule(&mut cpu_state, &rotations);

    let mut gpu_states = vec![patterned];
    gpu.permute_batch(&mut gpu_states, &rotations, ROUNDS);

    assert_eq!(
        cpu_state, gpu_states[0],
        "GPU permute of patterned state must match CPU"
    );
}

#[test]
fn gpu_permute_batch_all_match_cpu() {
    let gpu = gpu_or_skip();
    let rotations = KkSponge::new().rotations();

    // Build 64 distinct states
    let mut states: Vec<KkState> = (0..64)
        .map(|i| {
            let mut s: KkState = kk_iv();
            s[0] ^= i as u64;
            s[12] ^= (i as u64).wrapping_mul(0x123456789ABCDEF0);
            s
        })
        .collect();

    // CPU reference
    let mut cpu_states = states.clone();
    for s in cpu_states.iter_mut() {
        kk_permute_with_schedule(s, &rotations);
    }

    // GPU
    gpu.permute_batch(&mut states, &rotations, ROUNDS);

    for (i, (cpu, gpu_s)) in cpu_states.iter().zip(states.iter()).enumerate() {
        assert_eq!(cpu, gpu_s, "state {i} mismatch between CPU and GPU");
    }
}

#[test]
fn gpu_permute_batch_256_matches_cpu() {
    let gpu = gpu_or_skip();
    let rotations = KkSponge::new().rotations();

    let mut states: Vec<KkState> = (0..256)
        .map(|i| {
            let mut s: KkState = [0u64; STATE_WORDS];
            for w in 0..STATE_WORDS {
                s[w] = (i as u64 * 31 + w as u64 * 97) ^ 0xA5A5A5A5A5A5A5A5;
            }
            s
        })
        .collect();

    let mut cpu_states = states.clone();
    for s in cpu_states.iter_mut() {
        kk_permute_with_schedule(s, &rotations);
    }

    gpu.permute_batch(&mut states, &rotations, ROUNDS);

    for (i, (cpu, gpu_s)) in cpu_states.iter().zip(states.iter()).enumerate() {
        assert_eq!(cpu, gpu_s, "state {i} mismatch in 256-batch");
    }
}

// ─────────────────────────────────────────────────────────────────
//  KDF correctness
// ─────────────────────────────────────────────────────────────────

#[test]
fn gpu_kdf_single_matches_cpu() {
    let gpu = gpu_or_skip();

    let key = b"test-key-material";
    let salt = b"test-salt";
    let info = b"context-info-0";
    let output_len = 32;

    let cpu_out = kk_kdf(key, salt, info, output_len);
    let gpu_outs = gpu.kk_kdf_batch(key, salt, &[info.as_slice()], output_len);

    assert_eq!(gpu_outs.len(), 1);
    assert_eq!(
        cpu_out, gpu_outs[0],
        "GPU KDF single output must match CPU kk_kdf"
    );
}

#[test]
fn gpu_kdf_batch_matches_cpu() {
    let gpu = gpu_or_skip();

    let key = b"shared-secret-key";
    let salt = b"entropy-salt-value";
    let output_len = 64;

    let infos: Vec<Vec<u8>> = (0..32u32).map(|i| format!("info-{i}").into_bytes()).collect();
    let info_slices: Vec<&[u8]> = infos.iter().map(|v| v.as_slice()).collect();

    let gpu_outs = gpu.kk_kdf_batch(key, salt, &info_slices, output_len);

    assert_eq!(gpu_outs.len(), 32);
    for (i, gpu_out) in gpu_outs.iter().enumerate() {
        let cpu_out = kk_kdf(key, salt, &infos[i], output_len);
        assert_eq!(
            &cpu_out, gpu_out,
            "GPU KDF batch element {i} must match CPU kk_kdf"
        );
    }
}

#[test]
fn gpu_kdf_large_output_matches_cpu() {
    let gpu = gpu_or_skip();

    let key = b"big-output-key";
    let salt = b"big-output-salt";
    let output_len = 1024; // forces multiple squeeze rounds

    let infos: Vec<Vec<u8>> = (0..8u32).map(|i| i.to_le_bytes().to_vec()).collect();
    let info_slices: Vec<&[u8]> = infos.iter().map(|v| v.as_slice()).collect();

    let gpu_outs = gpu.kk_kdf_batch(key, salt, &info_slices, output_len);

    assert_eq!(gpu_outs.len(), 8);
    for (i, gpu_out) in gpu_outs.iter().enumerate() {
        assert_eq!(gpu_out.len(), output_len);
        let cpu_out = kk_kdf(key, salt, &infos[i], output_len);
        assert_eq!(
            &cpu_out, gpu_out,
            "GPU KDF 1024-byte output element {i} must match CPU"
        );
    }
}

#[test]
fn gpu_kdf_empty_info_matches_cpu() {
    let gpu = gpu_or_skip();

    let key = b"key";
    let salt = b"salt";
    let empty_info: &[u8] = b"";
    let output_len = 48;

    let cpu_out = kk_kdf(key, salt, empty_info, output_len);
    let gpu_outs = gpu.kk_kdf_batch(key, salt, &[empty_info], output_len);

    assert_eq!(
        cpu_out, gpu_outs[0],
        "GPU KDF with empty info must match CPU"
    );
}

#[test]
fn gpu_kdf_empty_salt_matches_cpu() {
    let gpu = gpu_or_skip();

    let key = b"key-material";
    let salt: &[u8] = b"";
    let info = b"some-context";
    let output_len = 32;

    let cpu_out = kk_kdf(key, salt, info, output_len);
    let gpu_outs = gpu.kk_kdf_batch(key, salt, &[info.as_slice()], output_len);

    assert_eq!(
        cpu_out, gpu_outs[0],
        "GPU KDF with empty salt must match CPU"
    );
}
