#!/usr/bin/env python3
"""
DDR Uniformity + Formal Bias Bound Tests
"""
import math
import random
from collections import Counter

DDR_MIX_8 = 0x2F

def ddr_8(a, b):
    s = ((b * DDR_MIX_8) & 0xFF) >> 5
    return ((a << s) | (a >> (8 - s))) & 0xFF if s else a

def mfr_8(a, b, rot):
    p = (a * (b | 1)) & 0xFF
    f = (p ^ (p >> 4) ^ b) & 0xFF
    return ((f << rot) | (f >> (8 - rot))) & 0xFF

def quintet_8(a, b, c, d, e, rot0, rot1):
    a = mfr_8(a, b, rot0)
    c = (c ^ a) & 0xFF
    d = ddr_8(d, c)
    e = mfr_8(e, d, rot1)
    b = (b ^ e) & 0xFF
    return a, b, c, d, e


# =======================================================
# TEST A: DDR rotation amount distribution
# =======================================================
print("=" * 60)
print("TEST A: DDR Rotation Amount Distribution")
print("=" * 60)

rot_counts = Counter()
for b in range(256):
    s = ((b * DDR_MIX_8) & 0xFF) >> 5
    rot_counts[s] += 1

print("\nRotation amount distribution over b in [0,255]:")
print("  Rot | Count | Fraction | Ideal=0.125")
print("  ----|-------|----------|------------")
for r in range(8):
    c = rot_counts[r]
    frac = c / 256
    dev = abs(frac - 0.125) / 0.125 * 100
    print(f"   {r}  |  {c:3d}  |  {frac:.4f}  | dev={dev:.1f}%")

expected = 32
chi_sq = sum((rot_counts[r] - expected) ** 2 / expected for r in range(8))
print(f"\nChi-sq (df=7): {chi_sq:.2f}  (critical p=0.05: 14.07)")
if chi_sq < 14.07:
    print("VERDICT: UNIFORM (cannot reject uniformity)")
else:
    print("VERDICT: NON-UNIFORM (bias detected)")

# --- MSB output position tracking ---
print("\n--- MSB output bit position after DDR(0x80, b) for all b ---")
bit_counts = Counter()
for b in range(256):
    s = ((b * DDR_MIX_8) & 0xFF) >> 5
    out = ((0x80 << s) | (0x80 >> (8 - s))) & 0xFF if s else 0x80
    for bit in range(8):
        if out & (1 << bit):
            bit_counts[bit] += 1

print("  Bit | Times set | Fraction | Status")
print("  ----|-----------|----------|-------")
for bit in range(8):
    c = bit_counts[bit]
    frac = c / 256
    status = "OK" if abs(frac - 0.125) < 0.05 else "BIASED"
    print(f"   {bit}  |    {c:3d}    |  {frac:.4f}  | {status}")

chi_sq_bit = sum((bit_counts[b] - expected) ** 2 / expected for b in range(8))
print(f"\nChi-sq (df=7): {chi_sq_bit:.2f}")
if chi_sq_bit < 14.07:
    print("VERDICT: MSB maps UNIFORMLY to all bit positions")
else:
    print("VERDICT: MSB has BIASED position mapping")


# =======================================================
# TEST B: Formal bias bound per round (statistical distance)
# =======================================================
print()
print("=" * 60)
print("TEST B: Formal Bias Bound (Statistical Distance from Uniform)")
print("=" * 60)
print()
print("Statistical distance (SD) = 0.5 * sum |P(x) - 1/N|")
print("  SD = 0     -> identical to uniform")
print("  SD = 1     -> completely distinguishable")
print("  SD < 2^-4  -> needs >2^8 samples to detect")
print()

random.seed(0x4B4B)
N = 262144

for da_label, da in [("0x01 (LSB)", 0x01), ("0x80 (MSB)", 0x80), ("0x55 (multi)", 0x55)]:
    print(f"--- Input da = {da_label} ---")
    print(f"  Rounds | chi-sq     | stat_dist      | max_bin_bias   | verdict")
    print(f"  -------|------------|----------------|----------------|--------")

    for nrounds in range(1, 6):
        bins = [0] * 256
        for _ in range(N):
            a = random.randint(0, 255)
            b = random.randint(0, 255)
            c = random.randint(0, 255)
            d = random.randint(0, 255)
            e = random.randint(0, 255)

            s1 = (a, b, c, d, e)
            s2 = (a ^ da, b, c, d, e)

            rots = [(3, 5), (5, 7), (2, 6), (7, 1), (4, 3)]
            for r in range(nrounds):
                r0, r1 = rots[r % len(rots)]
                s1 = quintet_8(*s1, r0, r1)
                s2 = quintet_8(*s2, r0, r1)

            out_diff = s1[0] ^ s2[0]
            bins[out_diff] += 1

        expected_count = N / 256
        chi_sq = sum((bins[i] - expected_count) ** 2 / expected_count for i in range(256))

        # Total variation distance
        stat_dist = 0.5 * sum(abs(bins[i] / N - 1 / 256) for i in range(256))

        # Max per-bin deviation
        max_bias = max(abs(bins[i] / N - 1 / 256) for i in range(256))

        verdict = "PASS" if chi_sq < 310 else "FAIL"

        if stat_dist > 0:
            sd_str = f"2^{math.log2(stat_dist):+.2f}"
        else:
            sd_str = "0"
        if max_bias > 0:
            mb_str = f"2^{math.log2(max_bias):+.2f}"
        else:
            mb_str = "0"

        print(f"    {nrounds}R   | {chi_sq:>10.0f} | {sd_str:>14s} | {mb_str:>14s} | {verdict}")

    print()
