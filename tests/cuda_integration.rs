//! CUDA correctness tests: verify CUDA produces identical output to CPU.
//!
//! Run with: `cargo test --features cuda --test cuda_integration`

#![cfg(feature = "cuda")]

use kk_crypto::cuda::CudaAccelerator;
use kk_crypto::kk_mix::{
    kk_kdf, kk_permute_with_schedule, KkSponge, KkState, ROUNDS, STATE_WORDS,
};

const ROUNDS_U32: u32 = ROUNDS as u32;

/// Get the KK_IV by reading a fresh sponge's state.
fn kk_iv() -> KkState {
    KkSponge::new().state()
}

/// Helper: create a CudaAccelerator or skip the test if no CUDA GPU available.
fn cuda_or_skip() -> CudaAccelerator {
    match CudaAccelerator::new() {
        Ok(c) => {
            eprintln!("CUDA test running on: {}", c.device_name());
            c
        }
        Err(e) => {
            eprintln!("Skipping CUDA test (no GPU): {e}");
            std::process::exit(0);
        }
    }
}

// ─────────────────────────────────────────────────────────────────
//  Permutation correctness
// ─────────────────────────────────────────────────────────────────

#[test]
fn cuda_permute_matches_cpu_iv_state() {
    let cuda = cuda_or_skip();
    let rotations = KkSponge::new().rotations();

    let mut cpu_state = kk_iv();
    kk_permute_with_schedule(&mut cpu_state, &rotations);

    let mut cuda_states = vec![kk_iv()];
    cuda.permute_batch(&mut cuda_states, &rotations, ROUNDS_U32);

    assert_eq!(
        cpu_state, cuda_states[0],
        "CUDA permute of KK_IV must match CPU"
    );
}

#[test]
fn cuda_permute_matches_cpu_zero_state() {
    let cuda = cuda_or_skip();
    let rotations = KkSponge::new().rotations();

    let zero_state: KkState = [0u64; STATE_WORDS];

    let mut cpu_state = zero_state;
    kk_permute_with_schedule(&mut cpu_state, &rotations);

    let mut cuda_states = vec![zero_state];
    cuda.permute_batch(&mut cuda_states, &rotations, ROUNDS_U32);

    assert_eq!(
        cpu_state, cuda_states[0],
        "CUDA permute of zero state must match CPU"
    );
}

#[test]
fn cuda_permute_matches_cpu_patterned_state() {
    let cuda = cuda_or_skip();
    let rotations = KkSponge::new().rotations();

    let mut patterned: KkState = [0u64; STATE_WORDS];
    for i in 0..STATE_WORDS {
        patterned[i] = (i as u64).wrapping_mul(0x9E3779B97F4A7C15) ^ 0xDEADBEEFCAFEBABE;
    }

    let mut cpu_state = patterned;
    kk_permute_with_schedule(&mut cpu_state, &rotations);

    let mut cuda_states = vec![patterned];
    cuda.permute_batch(&mut cuda_states, &rotations, ROUNDS_U32);

    assert_eq!(
        cpu_state, cuda_states[0],
        "CUDA permute of patterned state must match CPU"
    );
}

#[test]
fn cuda_permute_batch_all_match_cpu() {
    let cuda = cuda_or_skip();
    let rotations = KkSponge::new().rotations();

    let mut states: Vec<KkState> = (0..64)
        .map(|i| {
            let mut s: KkState = kk_iv();
            s[0] ^= i as u64;
            s[12] ^= (i as u64).wrapping_mul(0x123456789ABCDEF0);
            s
        })
        .collect();

    let mut cpu_states = states.clone();
    for s in cpu_states.iter_mut() {
        kk_permute_with_schedule(s, &rotations);
    }

    cuda.permute_batch(&mut states, &rotations, ROUNDS_U32);

    for (i, (cpu, cuda_s)) in cpu_states.iter().zip(states.iter()).enumerate() {
        assert_eq!(cpu, cuda_s, "state {i} mismatch between CPU and CUDA");
    }
}

#[test]
fn cuda_permute_batch_256_matches_cpu() {
    let cuda = cuda_or_skip();
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

    cuda.permute_batch(&mut states, &rotations, ROUNDS_U32);

    for (i, (cpu, cuda_s)) in cpu_states.iter().zip(states.iter()).enumerate() {
        assert_eq!(cpu, cuda_s, "state {i} mismatch in 256-batch");
    }
}

#[test]
fn cuda_permute_persistent_matches_cpu() {
    let cuda = cuda_or_skip();
    let rotations = KkSponge::new().rotations();

    let mut states: Vec<KkState> = (0..128)
        .map(|i| {
            let mut s = kk_iv();
            s[0] ^= i as u64;
            s
        })
        .collect();

    let mut cpu_states = states.clone();
    for s in cpu_states.iter_mut() {
        kk_permute_with_schedule(s, &rotations);
    }

    cuda.permute_batch_persistent(&mut states, &rotations, ROUNDS_U32);

    for (i, (cpu, cuda_s)) in cpu_states.iter().zip(states.iter()).enumerate() {
        assert_eq!(cpu, cuda_s, "persistent state {i} mismatch");
    }

    cuda.free_persistent();
}

// ─────────────────────────────────────────────────────────────────
//  KDF correctness
// ─────────────────────────────────────────────────────────────────

#[test]
fn cuda_kdf_single_matches_cpu() {
    let cuda = cuda_or_skip();

    let key = b"test-key-material";
    let salt = b"test-salt";
    let info = b"context-info-0";
    let output_len = 32;

    let cpu_out = kk_kdf(key, salt, info, output_len);
    let cuda_outs = cuda.kk_kdf_batch(key, salt, &[info.as_slice()], output_len);

    assert_eq!(cuda_outs.len(), 1);
    assert_eq!(
        cpu_out, cuda_outs[0],
        "CUDA KDF single output must match CPU kk_kdf"
    );
}

#[test]
fn cuda_kdf_batch_matches_cpu() {
    let cuda = cuda_or_skip();

    let key = b"shared-secret-key";
    let salt = b"entropy-salt-value";
    let output_len = 64;

    let infos: Vec<Vec<u8>> = (0..32u32).map(|i| format!("info-{i}").into_bytes()).collect();
    let info_slices: Vec<&[u8]> = infos.iter().map(|v| v.as_slice()).collect();

    let cuda_outs = cuda.kk_kdf_batch(key, salt, &info_slices, output_len);

    assert_eq!(cuda_outs.len(), 32);
    for (i, cuda_out) in cuda_outs.iter().enumerate() {
        let cpu_out = kk_kdf(key, salt, &infos[i], output_len);
        assert_eq!(
            &cpu_out, cuda_out,
            "CUDA KDF batch element {i} must match CPU kk_kdf"
        );
    }
}

#[test]
fn cuda_kdf_large_output_matches_cpu() {
    let cuda = cuda_or_skip();

    let key = b"big-output-key";
    let salt = b"big-output-salt";
    let output_len = 1024;

    let infos: Vec<Vec<u8>> = (0..8u32).map(|i| i.to_le_bytes().to_vec()).collect();
    let info_slices: Vec<&[u8]> = infos.iter().map(|v| v.as_slice()).collect();

    let cuda_outs = cuda.kk_kdf_batch(key, salt, &info_slices, output_len);

    assert_eq!(cuda_outs.len(), 8);
    for (i, cuda_out) in cuda_outs.iter().enumerate() {
        assert_eq!(cuda_out.len(), output_len);
        let cpu_out = kk_kdf(key, salt, &infos[i], output_len);
        assert_eq!(
            &cpu_out, cuda_out,
            "CUDA KDF 1024-byte output element {i} must match CPU"
        );
    }
}
