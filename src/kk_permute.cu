// Copyright (c) 2026 John A Keeney, Entrouter. All rights reserved.
// Licensed under the Apache License, Version 2.0 with Additional Terms.
// NO COMMERCIAL USE without prior written authorization from Entrouter.
// Unauthorized commercial use will be prosecuted to the fullest extent of the law.
// See the LICENSE file in the project root for full license information.
// NOTICE: Removal of this header is a violation of the license.

// ─────────────────────────────────────────────────────────────────
//  KK Permutation  - CUDA kernel with native uint64_t
//
//  No u64 emulation. Native 64-bit multiply, shift, rotate.
//  Each CUDA thread processes one independent 1600-bit state.
// ─────────────────────────────────────────────────────────────────

#include <cstdint>
#include <cstring>

#define STATE_WORDS  25
#define RATE_WORDS   19
#define CAPACITY_WORDS 6

// Diagonal index patterns for the 5×5 grid (constant memory, broadcast-cached)
__constant__ unsigned int c_diags[5][5] = {
    {0, 6, 12, 18, 24},
    {1, 7, 13, 19, 20},
    {2, 8, 14, 15, 21},
    {3, 9, 10, 16, 22},
    {4, 5, 11, 17, 23},
};

// Round constants for injection at grid corners + center
__constant__ uint64_t RC4  = 0x9E3779B97F4A7C15ULL;
__constant__ uint64_t RC12 = 0xB7E151628AED2A6AULL;
__constant__ uint64_t RC20 = 0x243F6A8885A2F7A4ULL;
__constant__ uint64_t RC24 = 0x298B075B4B6A5240ULL;

// ── Rotate-left for 64-bit values ──────────────────────────────
__device__ __forceinline__ uint64_t rotl64(uint64_t v, unsigned int n) {
    n &= 63;
    return (v << n) | (v >> ((64u - n) & 63u));
}

// ── Multiply-Fold-Rotate (MFR) ────────────────────────────────
// a ×₆₄ (b|1), fold high→low, rotate
__device__ __forceinline__ uint64_t mfr(uint64_t a, uint64_t b, unsigned int rot) {
    uint64_t product = a * (b | 1ULL);
    uint64_t folded  = product ^ (product >> 32);
    return rotl64(folded, rot);
}

// ── Data-Dependent Rotation (DDR) ──────────────────────────────
// Constant-time: 6 conditional fixed rotations by powers of 2
__device__ __forceinline__ uint64_t ddr(uint64_t a, uint64_t b) {
    uint64_t folded = b ^ (b >> 32);
    unsigned int s = (unsigned int)((folded ^ (folded >> 16) ^ (folded >> 8)) & 63ULL);

    uint64_t v = a;
    uint64_t m;

    m = 0ULL - (uint64_t)(s & 1u);
    v = (v & ~m) | (rotl64(v, 1) & m);
    m = 0ULL - (uint64_t)((s >> 1) & 1u);
    v = (v & ~m) | (rotl64(v, 2) & m);
    m = 0ULL - (uint64_t)((s >> 2) & 1u);
    v = (v & ~m) | (rotl64(v, 4) & m);
    m = 0ULL - (uint64_t)((s >> 3) & 1u);
    v = (v & ~m) | (rotl64(v, 8) & m);
    m = 0ULL - (uint64_t)((s >> 4) & 1u);
    v = (v & ~m) | (rotl64(v, 16) & m);
    m = 0ULL - (uint64_t)((s >> 5) & 1u);
    v = (v & ~m) | (rotl64(v, 32) & m);

    return v;
}

// ── Quintet-round: 5-word mixer ────────────────────────────────
__device__ __forceinline__ void quintet_round(
    uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d, uint64_t &e,
    unsigned int rot0, unsigned int rot1
) {
    a = mfr(a, b, rot0);
    c ^= a;
    d = ddr(d, c);
    e = mfr(e, d, rot1);
    b ^= e;
}

// ── Main permutation kernel ────────────────────────────────────
// One thread per state. Each state = 25 × u64 = 200 bytes.
__global__ void kk_permute_kernel(
    uint64_t* __restrict__ states,
    const unsigned int* __restrict__ rotations,
    unsigned int rounds,
    unsigned int num_states
) {
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num_states) return;

    // Load state into registers (25 u64s)
    uint64_t s[STATE_WORDS];
    uint64_t* base = states + (uint64_t)idx * STATE_WORDS;
    #pragma unroll
    for (int i = 0; i < STATE_WORDS; i++) {
        s[i] = base[i];
    }

    // Load rotations into registers (30 u32s)
    unsigned int rot[30];
    #pragma unroll
    for (int i = 0; i < 30; i++) {
        rot[i] = rotations[i];
    }

    for (unsigned int round = 0; round < rounds; round++) {
        uint64_t r = (uint64_t)round;

        // ── Row phase: 5 quintet-rounds ──
        #pragma unroll
        for (int row = 0; row < 5; row++) {
            int b = row * 5;
            quintet_round(s[b], s[b+1], s[b+2], s[b+3], s[b+4],
                          rot[row * 2], rot[row * 2 + 1]);
        }

        // ── Column phase: 5 quintet-rounds ──
        #pragma unroll
        for (int col = 0; col < 5; col++) {
            quintet_round(s[col], s[col+5], s[col+10], s[col+15], s[col+20],
                          rot[10 + col * 2], rot[10 + col * 2 + 1]);
        }

        // ── Diagonal phase: 5 quintet-rounds ──
        #pragma unroll
        for (int d = 0; d < 5; d++) {
            quintet_round(
                s[c_diags[d][0]], s[c_diags[d][1]], s[c_diags[d][2]],
                s[c_diags[d][3]], s[c_diags[d][4]],
                rot[20 + d * 2], rot[20 + d * 2 + 1]
            );
        }

        // ── Round constant injection (corners + center) ──
        s[0]  += r;
        s[4]  += r * RC4;
        s[12] += r * RC12;
        s[20] += r * RC20;
        s[24] += r * RC24;

        // ── Intra-round re-keying every 8 rounds ──
        if ((round & 7u) == 7u) {
            #pragma unroll
            for (int i = 0; i < RATE_WORDS; i++) {
                s[i] ^= rotl64(s[RATE_WORDS + (i % CAPACITY_WORDS)], round);
            }
        }
    }

    // Write state back to global memory
    #pragma unroll
    for (int i = 0; i < STATE_WORDS; i++) {
        base[i] = s[i];
    }
}

// ═══════════════════════════════════════════════════════════════
//  Host-side C API (called from Rust via FFI)
// ═══════════════════════════════════════════════════════════════

extern "C" int kk_cuda_is_available() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    return (err == cudaSuccess && count > 0) ? 1 : 0;
}

extern "C" int kk_cuda_get_device_name(char* buf, int buf_len) {
    cudaDeviceProp prop;
    cudaError_t err = cudaGetDeviceProperties(&prop, 0);
    if (err != cudaSuccess) return -1;
    strncpy(buf, prop.name, (size_t)(buf_len - 1));
    buf[buf_len - 1] = '\0';
    return 0;
}

/// Permute N independent states on the GPU.
/// host_states: N * 25 uint64_t values (in-place, host memory).
/// host_rotations: 30 uint32_t values (rotation schedule).
/// Returns 0 on success, negative on error.
extern "C" int kk_cuda_permute_batch(
    uint64_t* host_states,
    const unsigned int* host_rotations,
    unsigned int rounds,
    unsigned int num_states
) {
    if (num_states == 0) return 0;

    size_t state_bytes = (size_t)num_states * STATE_WORDS * sizeof(uint64_t);
    size_t rot_bytes   = 30 * sizeof(unsigned int);

    uint64_t*     d_states    = nullptr;
    unsigned int* d_rotations = nullptr;

    cudaError_t err;

    err = cudaMalloc(&d_states, state_bytes);
    if (err != cudaSuccess) return -1;

    err = cudaMalloc(&d_rotations, rot_bytes);
    if (err != cudaSuccess) { cudaFree(d_states); return -2; }

    cudaMemcpy(d_states,    host_states,    state_bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_rotations, host_rotations, rot_bytes,   cudaMemcpyHostToDevice);

    int block_size = 256;
    int grid_size  = ((int)num_states + block_size - 1) / block_size;
    kk_permute_kernel<<<grid_size, block_size>>>(
        d_states, d_rotations, rounds, num_states
    );

    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        cudaFree(d_states);
        cudaFree(d_rotations);
        return -3;
    }

    cudaMemcpy(host_states, d_states, state_bytes, cudaMemcpyDeviceToHost);

    cudaFree(d_states);
    cudaFree(d_rotations);
    return 0;
}

/// Persistent GPU buffers for amortized allocation overhead.
/// Allocated lazily on first use, freed at process exit.
static uint64_t*     g_d_states    = nullptr;
static unsigned int* g_d_rotations = nullptr;
static size_t        g_capacity    = 0;

extern "C" int kk_cuda_permute_batch_persistent(
    uint64_t* host_states,
    const unsigned int* host_rotations,
    unsigned int rounds,
    unsigned int num_states
) {
    if (num_states == 0) return 0;

    size_t need = (size_t)num_states * STATE_WORDS;

    // (Re)allocate if needed
    if (need > g_capacity) {
        if (g_d_states)    cudaFree(g_d_states);
        if (g_d_rotations) cudaFree(g_d_rotations);

        cudaError_t err;
        err = cudaMalloc(&g_d_states, need * sizeof(uint64_t));
        if (err != cudaSuccess) { g_capacity = 0; return -1; }
        err = cudaMalloc(&g_d_rotations, 30 * sizeof(unsigned int));
        if (err != cudaSuccess) { cudaFree(g_d_states); g_capacity = 0; return -2; }

        g_capacity = need;
    }

    size_t state_bytes = need * sizeof(uint64_t);
    cudaMemcpy(g_d_states,    host_states,    state_bytes,               cudaMemcpyHostToDevice);
    cudaMemcpy(g_d_rotations, host_rotations, 30 * sizeof(unsigned int), cudaMemcpyHostToDevice);

    int block_size = 256;
    int grid_size  = ((int)num_states + block_size - 1) / block_size;
    kk_permute_kernel<<<grid_size, block_size>>>(
        g_d_states, g_d_rotations, rounds, num_states
    );

    cudaError_t err = cudaDeviceSynchronize();
    if (err != cudaSuccess) return -3;

    cudaMemcpy(host_states, g_d_states, state_bytes, cudaMemcpyDeviceToHost);
    return 0;
}

extern "C" void kk_cuda_free_persistent() {
    if (g_d_states)    { cudaFree(g_d_states);    g_d_states    = nullptr; }
    if (g_d_rotations) { cudaFree(g_d_rotations); g_d_rotations = nullptr; }
    g_capacity = 0;
}
