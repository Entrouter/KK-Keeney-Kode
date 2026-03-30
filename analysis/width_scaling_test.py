#!/usr/bin/env python3
"""
KK Width-Scaling Validation
============================
16-bit and 32-bit models to confirm whether 8-bit results scale.

Tests:
  A. DDR rotation selector uniformity (exhaustive)
  B. MSB → output bit position mapping (exhaustive)
  C. Multi-round bias convergence (sampling, N=2^20)
  D. Reduced-round distinguisher (sampling, N=2^20)
  E. Trail clustering (sampling)

Skipped: Algebraic degree (2^32 truth table infeasible at 16-bit).
"""

import math
import random
import sys
import time
from collections import Counter

# ─────────────────────────────────────────────────────────────────
#  16-bit Primitives
# ─────────────────────────────────────────────────────────────────

BITS_16 = 16
MASK_16 = 0xFFFF
DDR_MIX_16 = 0x3B2F          # low 16 bits of 0xB5C0FBCFEC4D3B2F
DDR_SEL_BITS_16 = 4           # log2(16) = 4 rotation amounts
DDR_SEL_SHIFT_16 = 16 - 4    # >> 12

def rotl16(v, r):
    r = r % 16
    return ((v << r) | (v >> (16 - r))) & MASK_16

def mfr_16(a, b, rot):
    p = (a * (b | 1)) & MASK_16
    f = (p ^ (p >> 8) ^ b) & MASK_16    # fold at half-width
    return rotl16(f, rot)

def ddr_16(a, b):
    s = ((b * DDR_MIX_16) & MASK_16) >> DDR_SEL_SHIFT_16
    return rotl16(a, s) if s else a

def quintet_16(a, b, c, d, e, rot0, rot1):
    a = mfr_16(a, b, rot0)
    c = (c ^ a) & MASK_16
    d = ddr_16(d, c)
    e = mfr_16(e, d, rot1)
    b = (b ^ e) & MASK_16
    return a, b, c, d, e


# ─────────────────────────────────────────────────────────────────
#  32-bit Primitives
# ─────────────────────────────────────────────────────────────────

BITS_32 = 32
MASK_32 = 0xFFFFFFFF
DDR_MIX_32 = 0xEC4D3B2F      # low 32 bits of 0xB5C0FBCFEC4D3B2F
DDR_SEL_BITS_32 = 5           # log2(32) = 5 rotation amounts
DDR_SEL_SHIFT_32 = 32 - 5    # >> 27

def rotl32(v, r):
    r = r % 32
    return ((v << r) | (v >> (32 - r))) & MASK_32

def mfr_32(a, b, rot):
    p = (a * (b | 1)) & MASK_32
    f = (p ^ (p >> 16) ^ b) & MASK_32
    return rotl32(f, rot)

def ddr_32(a, b):
    s = ((b * DDR_MIX_32) & MASK_32) >> DDR_SEL_SHIFT_32
    return rotl32(a, s) if s else a

def quintet_32(a, b, c, d, e, rot0, rot1):
    a = mfr_32(a, b, rot0)
    c = (c ^ a) & MASK_32
    d = ddr_32(d, c)
    e = mfr_32(e, d, rot1)
    b = (b ^ e) & MASK_32
    return a, b, c, d, e


# ═════════════════════════════════════════════════════════════════
#  TEST A: DDR Rotation Selector Uniformity (exhaustive)
# ═════════════════════════════════════════════════════════════════

def test_ddr_uniformity(bits, mask, ddr_mix, sel_shift, n_rots):
    N = 1 << bits
    expected = N // n_rots

    print(f"\n{'='*60}")
    print(f"TEST A: DDR Rotation Selector Uniformity ({bits}-bit)")
    print(f"{'='*60}")
    print(f"  Exhaustive over all {N:,} values of b")
    print(f"  {n_rots} rotation amounts, expected {expected:,} each\n")

    t0 = time.time()
    rot_counts = Counter()
    for b in range(N):
        s = ((b * ddr_mix) & mask) >> sel_shift
        rot_counts[s] += 1

    elapsed = time.time() - t0

    print(f"  Rot | Count     | Expected  | Deviation")
    print(f"  ----|-----------|-----------|----------")
    for r in range(n_rots):
        c = rot_counts[r]
        dev = c - expected
        print(f"  {r:>3} | {c:>9,} | {expected:>9,} | {dev:+d}")

    chi_sq = sum((rot_counts[r] - expected) ** 2 / expected for r in range(n_rots))
    df = n_rots - 1
    # Critical chi-sq at p=0.05
    crit = {7: 14.07, 15: 25.00, 31: 44.99}.get(df, df * 1.5)
    p_str = "1.000" if chi_sq == 0 else f"< 0.05" if chi_sq > crit else "> 0.05"

    print(f"\n  chi-sq = {chi_sq:.4f}  (df={df}, critical p=0.05: {crit:.2f})")
    if chi_sq == 0:
        print(f"  PERFECTLY UNIFORM (exact equipartition)")
    elif chi_sq < crit:
        print(f"  UNIFORM (no significant deviation)")
    else:
        print(f"  NON-UNIFORM (bias detected)")
    print(f"  Time: {elapsed:.1f}s")

    return chi_sq


# ═════════════════════════════════════════════════════════════════
#  TEST B: MSB → Output Bit Position Mapping (exhaustive)
# ═════════════════════════════════════════════════════════════════

def test_msb_mapping(bits, mask, ddr_mix, sel_shift, n_rots):
    N = 1 << bits
    msb = 1 << (bits - 1)
    expected = N // n_rots  # each bit position hit equally

    print(f"\n{'='*60}")
    print(f"TEST B: MSB Output Position Mapping ({bits}-bit)")
    print(f"{'='*60}")
    print(f"  DDR(0x{msb:0{bits//4}X}, b) for all {N:,} values of b")
    print(f"  Tracking which output bit the MSB difference lands on\n")

    t0 = time.time()
    bit_counts = Counter()
    for b in range(N):
        s = ((b * ddr_mix) & mask) >> sel_shift
        if s:
            out = ((msb << s) | (msb >> (bits - s))) & mask
        else:
            out = msb
        for bit in range(bits):
            if out & (1 << bit):
                bit_counts[bit] += 1

    elapsed = time.time() - t0

    print(f"  Bit | Count     | Expected  | Deviation")
    print(f"  ----|-----------|-----------|----------")
    for bit in range(bits):
        c = bit_counts[bit]
        dev = c - expected
        print(f"  {bit:>3} | {c:>9,} | {expected:>9,} | {dev:+d}")

    chi_sq = sum((bit_counts[b] - expected) ** 2 / expected for b in range(bits))
    df = bits - 1

    print(f"\n  chi-sq = {chi_sq:.4f}  (df={df})")
    if chi_sq == 0:
        print(f"  PERFECTLY UNIFORM (MSB redistributed exactly)")
    elif chi_sq < df * 2:
        print(f"  UNIFORM (no significant deviation)")
    else:
        print(f"  NON-UNIFORM (bias detected)")
    print(f"  Time: {elapsed:.1f}s")

    return chi_sq


# ═════════════════════════════════════════════════════════════════
#  TEST C: Multi-Round Bias Convergence (sampling)
# ═════════════════════════════════════════════════════════════════

def test_bias_convergence(bits, mask, quintet_fn, label):
    N_SAMPLES = 1 << 20  # 1,048,576
    msb = 1 << (bits - 1)
    n_bins = min(1 << bits, 65536)  # cap bins at 65536 for sanity
    trunc_mask = n_bins - 1

    print(f"\n{'='*60}")
    print(f"TEST C: Bias Convergence ({label})")
    print(f"{'='*60}")
    print(f"  Samples: {N_SAMPLES:,}")
    print(f"  Output bins: {n_bins:,} (truncated to low {int(math.log2(n_bins))} bits)")
    print(f"  Pass threshold: eps < 2^-{bits-2}\n")

    random.seed(0x4B4B_1616)
    rot_schedule = [(3, 5), (5, 7), (7, 3), (3, 7), (6, 2)]

    for da_label, da in [("LSB", 0x01), ("MSB", msb), ("multi", (mask + 1) // 3)]:
        print(f"  --- da = 0x{da:0{bits//4}X} ({da_label}) ---")
        print(f"  Rounds | stat_dist       | chi-sq       | verdict")
        print(f"  -------|-----------------|--------------|--------")

        for nrounds in range(1, 6):
            bins = [0] * n_bins
            for _ in range(N_SAMPLES):
                a = random.randint(0, mask)
                b = random.randint(0, mask)
                c = random.randint(0, mask)
                d = random.randint(0, mask)
                e = random.randint(0, mask)

                s1 = (a, b, c, d, e)
                s2 = (a ^ da, b, c, d, e)

                for r in range(nrounds):
                    r0, r1 = rot_schedule[r % len(rot_schedule)]
                    s1 = quintet_fn(*s1, r0, r1)
                    s2 = quintet_fn(*s2, r0, r1)

                diff = (s1[0] ^ s2[0]) & trunc_mask
                bins[diff] += 1

            expected_count = N_SAMPLES / n_bins
            chi_sq = sum((bins[i] - expected_count) ** 2 / expected_count
                         for i in range(n_bins))

            stat_dist = 0.5 * sum(abs(bins[i] / N_SAMPLES - 1 / n_bins)
                                   for i in range(n_bins))

            if stat_dist > 0:
                sd_str = f"2^{math.log2(stat_dist):+.2f}"
            else:
                sd_str = "0"

            # df = n_bins - 1, critical at p=0.001 ~ n_bins + 3*sqrt(2*n_bins)
            critical = n_bins + 3 * math.sqrt(2 * n_bins)
            verdict = "PASS" if chi_sq < critical else "FAIL"

            print(f"    {nrounds}R   | {sd_str:>15s} | {chi_sq:>12.0f} | {verdict}")

        print()


# ═════════════════════════════════════════════════════════════════
#  TEST D: Reduced-Round Distinguisher (sampling)
# ═════════════════════════════════════════════════════════════════

def test_distinguisher(bits, mask, quintet_fn, label):
    N_SAMPLES = 1 << 20
    msb = 1 << (bits - 1)
    n_bins = min(1 << bits, 65536)
    trunc_mask = n_bins - 1

    print(f"\n{'='*60}")
    print(f"TEST D: Reduced-Round Distinguisher ({label})")
    print(f"{'='*60}")
    print(f"  Samples: {N_SAMPLES:,}, bins: {n_bins:,}")
    print(f"  Expected chi-sq ~ {n_bins - 1}")
    print(f"  Critical (p=0.001) ~ {n_bins + 3*math.sqrt(2*n_bins):.0f}\n")

    random.seed(0x4B4B_D157)
    rot_schedule = [(3, 5), (5, 7), (7, 3), (3, 7), (6, 2)]

    for da_label, da in [("LSB", 0x01), ("MSB", msb), ("multi", 0x55)]:
        print(f"  da=0x{da:0{bits//4}X} ({da_label}):")
        for nrounds in range(1, 6):
            bins = [0] * n_bins
            for _ in range(N_SAMPLES):
                a = random.randint(0, mask)
                b = random.randint(0, mask)
                c = random.randint(0, mask)
                d = random.randint(0, mask)
                e = random.randint(0, mask)

                s1 = (a, b, c, d, e)
                s2 = (a ^ da, b, c, d, e)

                for r in range(nrounds):
                    r0, r1 = rot_schedule[r % len(rot_schedule)]
                    s1 = quintet_fn(*s1, r0, r1)
                    s2 = quintet_fn(*s2, r0, r1)

                diff = (s1[0] ^ s2[0]) & trunc_mask
                bins[diff] += 1

            expected_count = N_SAMPLES / n_bins
            chi_sq = sum((bins[i] - expected_count) ** 2 / expected_count
                         for i in range(n_bins))

            critical = n_bins + 3 * math.sqrt(2 * n_bins)
            verdict = "PASS" if chi_sq < critical else "FAIL"
            print(f"    {nrounds}R: chi_sq={chi_sq:>12.0f}  [{verdict}]")
        print()


# ═════════════════════════════════════════════════════════════════
#  TEST E: Trail Clustering (sampling)
# ═════════════════════════════════════════════════════════════════

def test_trail_clustering(bits, mask, quintet_fn, label):
    N_SAMPLES = 1 << 18  # 262,144

    print(f"\n{'='*60}")
    print(f"TEST E: Trail Clustering ({label})")
    print(f"{'='*60}")
    print(f"  Samples per input diff: {N_SAMPLES:,}\n")

    random.seed(0x4B4B_7241)
    msb = 1 << (bits - 1)

    for nrounds, round_label in [(1, "1R"), (2, "2R")]:
        print(f"  --- {round_label} ---")
        for da_label, da in [("LSB", 0x01), ("MSB", msb), ("multi", 0xFF)]:
            output_diffs = Counter()
            for _ in range(N_SAMPLES):
                a = random.randint(0, mask)
                b = random.randint(0, mask)
                c = random.randint(0, mask)
                d = random.randint(0, mask)
                e = random.randint(0, mask)

                s1 = (a, b, c, d, e)
                s2 = (a ^ da, b, c, d, e)

                rots = [(3, 5), (5, 7)]
                for r in range(nrounds):
                    r0, r1 = rots[r % len(rots)]
                    s1 = quintet_fn(*s1, r0, r1)
                    s2 = quintet_fn(*s2, r0, r1)

                diff = tuple((x ^ y) & mask for x, y in zip(s1, s2))
                output_diffs[diff] += 1

            n_unique = len(output_diffs)
            top1_frac = output_diffs.most_common(1)[0][1] / N_SAMPLES
            print(f"    da=0x{da:0{bits//4}X} ({da_label}): {n_unique:>8,} unique, top1={top1_frac:.6f}")
        print()


# ═════════════════════════════════════════════════════════════════
#  Main
# ═════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    total_t0 = time.time()

    print("=" * 60)
    print("KK WIDTH-SCALING VALIDATION")
    print("=" * 60)

    # ── 16-BIT ──────────────────────────────────────────────────
    print("\n" + "#" * 60)
    print("#  16-BIT MODEL")
    print("#" * 60)

    ddr16_chi = test_ddr_uniformity(16, MASK_16, DDR_MIX_16, DDR_SEL_SHIFT_16, 16)
    msb16_chi = test_msb_mapping(16, MASK_16, DDR_MIX_16, DDR_SEL_SHIFT_16, 16)
    test_bias_convergence(16, MASK_16, quintet_16, "16-bit")
    test_distinguisher(16, MASK_16, quintet_16, "16-bit")
    test_trail_clustering(16, MASK_16, quintet_16, "16-bit")

    # ── 32-BIT DDR ONLY ────────────────────────────────────────
    # Full 32-bit quintet tests would be very slow in pure Python.
    # DDR uniformity is feasible with a loop over 2^32 values.
    print("\n" + "#" * 60)
    print("#  32-BIT MODEL (DDR uniformity only)")
    print("#" * 60)
    print("  Note: 4,294,967,296 iterations — this will take a while...")

    try:
        import numpy as np
        HAS_NUMPY = True
    except ImportError:
        HAS_NUMPY = False

    if HAS_NUMPY:
        print("\n" + "=" * 60)
        print("TEST A: DDR Rotation Selector Uniformity (32-bit, numpy)")
        print("=" * 60)
        t0 = time.time()
        n_rots_32 = 32
        expected_32 = (1 << 32) // n_rots_32  # 134,217,728

        rot_counts_32 = np.zeros(n_rots_32, dtype=np.int64)
        chunk = 1 << 24  # 16M at a time
        total = 1 << 32

        for start in range(0, total, chunk):
            end = min(start + chunk, total)
            b = np.arange(start, end, dtype=np.uint64)
            s = ((b * np.uint64(DDR_MIX_32)) & np.uint64(MASK_32)) >> np.uint64(DDR_SEL_SHIFT_32)
            for r in range(n_rots_32):
                rot_counts_32[r] += np.sum(s == r)
            if (start // chunk) % 16 == 0:
                pct = start / total * 100
                print(f"    Progress: {pct:.0f}% ({start:,}/{total:,})", flush=True)

        elapsed = time.time() - t0
        print(f"    Progress: 100%\n")

        print(f"  Rot | Count         | Expected      | Deviation")
        print(f"  ----|---------------|---------------|----------")
        for r in range(n_rots_32):
            c = int(rot_counts_32[r])
            dev = c - expected_32
            print(f"  {r:>3} | {c:>13,} | {expected_32:>13,} | {dev:+d}")

        chi_sq_32 = sum(float((rot_counts_32[r] - expected_32) ** 2) / expected_32
                        for r in range(n_rots_32))
        print(f"\n  chi-sq = {chi_sq_32:.4f}  (df={n_rots_32-1})")
        if chi_sq_32 == 0:
            print(f"  PERFECTLY UNIFORM")
        elif chi_sq_32 < 44.99:
            print(f"  UNIFORM (no significant deviation)")
        else:
            print(f"  NON-UNIFORM")
        print(f"  Time: {elapsed:.1f}s")

        # 32-bit MSB mapping
        print(f"\n{'='*60}")
        print(f"TEST B: MSB Output Position Mapping (32-bit, numpy)")
        print(f"{'='*60}")
        t0 = time.time()
        msb_32 = np.uint64(1 << 31)
        bit_counts_32 = np.zeros(32, dtype=np.int64)

        for start in range(0, total, chunk):
            end = min(start + chunk, total)
            b = np.arange(start, end, dtype=np.uint64)
            s = ((b * np.uint64(DDR_MIX_32)) & np.uint64(MASK_32)) >> np.uint64(DDR_SEL_SHIFT_32)
            # Compute rotation of MSB
            out = np.where(s > 0,
                           ((msb_32 << s) | (msb_32 >> (np.uint64(32) - s))) & np.uint64(MASK_32),
                           msb_32)
            for bit in range(32):
                bit_counts_32[bit] += np.sum((out >> np.uint64(bit)) & np.uint64(1))
            if (start // chunk) % 16 == 0:
                pct = start / total * 100
                print(f"    Progress: {pct:.0f}%", flush=True)

        elapsed = time.time() - t0
        print(f"    Progress: 100%\n")

        expected_bit = expected_32
        print(f"  Bit | Count         | Expected      | Deviation")
        print(f"  ----|---------------|---------------|----------")
        for bit in range(32):
            c = int(bit_counts_32[bit])
            dev = c - expected_bit
            print(f"  {bit:>3} | {c:>13,} | {expected_bit:>13,} | {dev:+d}")

        chi_sq_msb_32 = sum(float((bit_counts_32[b] - expected_bit) ** 2) / expected_bit
                            for b in range(32))
        print(f"\n  chi-sq = {chi_sq_msb_32:.4f}")
        if chi_sq_msb_32 == 0:
            print(f"  PERFECTLY UNIFORM")
        elif chi_sq_msb_32 < 44.99:
            print(f"  UNIFORM")
        else:
            print(f"  NON-UNIFORM")
        print(f"  Time: {elapsed:.1f}s")
    else:
        print("\n  numpy not available — skipping 32-bit exhaustive test.")
        print("  Install numpy: pip install numpy")

    total_elapsed = time.time() - total_t0
    print(f"\n{'='*60}")
    print(f"ALL TESTS COMPLETE — Total time: {total_elapsed:.1f}s")
    print(f"{'='*60}")
