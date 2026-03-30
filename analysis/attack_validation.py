#!/usr/bin/env python3
"""
KK Attack Validation Suite
==========================
5 tests covering: fold comparison, trail clustering, MSB propagation,
algebraic degree, and reduced-round distinguisher.

All tests operate at 8-bit width for exhaustive feasibility.
Results are printed and collected for the summary report.
"""

import math
import sys
import time
from collections import defaultdict, Counter

# ─────────────────────────────────────────────────────────────────
#  8-bit Primitives (matching src/kk_mix.rs scaled to 8-bit)
# ─────────────────────────────────────────────────────────────────

DDR_MIX_8 = 0x2F  # low byte of 0xB5C0FBCFEC4D3B2F

def mfr_8(a, b, rot):
    """Current MFR: fold = p ^ (p >> 4) ^ b"""
    p = (a * (b | 1)) & 0xFF
    f = (p ^ (p >> 4) ^ b) & 0xFF
    return ((f << rot) | (f >> (8 - rot))) & 0xFF

def mfr_8_byteswap(a, b, rot):
    """Proposed MFR: fold = p ^ nibble_swap(p) ^ b
    Nibble-swap is the 8-bit analogue of 64-bit BSWAP.
    Swaps high nibble and low nibble: bits 0-3 <-> bits 4-7."""
    p = (a * (b | 1)) & 0xFF
    ps = ((p >> 4) | (p << 4)) & 0xFF  # nibble swap
    f = (p ^ ps ^ b) & 0xFF
    return ((f << rot) | (f >> (8 - rot))) & 0xFF

def ddr_8(a, b):
    """DDR at 8-bit: 3-bit selector from top bits of b*DDR_MIX."""
    s = ((b * DDR_MIX_8) & 0xFF) >> 5  # top 3 bits
    return ((a << s) | (a >> (8 - s))) & 0xFF if s else a

def quintet_8(a, b, c, d, e, rot0, rot1):
    """Full quintet at 8-bit."""
    a = mfr_8(a, b, rot0)
    c = (c ^ a) & 0xFF
    d = ddr_8(d, c)
    e = mfr_8(e, d, rot1)
    b = (b ^ e) & 0xFF
    return a, b, c, d, e

def quintet_8_byteswap(a, b, c, d, e, rot0, rot1):
    """Full quintet with proposed nibble-swap fold."""
    a = mfr_8_byteswap(a, b, rot0)
    c = (c ^ a) & 0xFF
    d = ddr_8(d, c)
    e = mfr_8_byteswap(e, d, rot1)
    b = (b ^ e) & 0xFF
    return a, b, c, d, e

RESULTS = {}

# ═════════════════════════════════════════════════════════════════
#  TEST 1: Fold Comparison DDT
# ═════════════════════════════════════════════════════════════════

def compute_mdp_profile(mfr_fn, rot=3):
    """Compute per-bit MDP for given MFR function."""
    mdps = []
    for k in range(8):
        da = 1 << k
        counts = {}
        for a in range(256):
            for b in range(256):
                dy = mfr_fn(a, b, rot) ^ mfr_fn(a ^ da, b, rot)
                counts[dy] = counts.get(dy, 0) + 1
        mdp = max(counts.values()) / 65536
        log_mdp = math.log2(mdp) if mdp > 0 else float('-inf')
        mdps.append((k, mdp, log_mdp))
    return mdps

def compute_global_mdp(mfr_fn, rot=3):
    """Compute global MDP: max over ALL (da, dy) pairs where da != 0."""
    global_max = 0
    global_pair = (0, 0)
    for da in range(1, 256):
        counts = {}
        for a in range(256):
            for b in range(256):
                dy = mfr_fn(a, b, rot) ^ mfr_fn(a ^ da, b, rot)
                counts[dy] = counts.get(dy, 0) + 1
        for dy, cnt in counts.items():
            if cnt > global_max:
                global_max = cnt
                global_pair = (da, dy)
    return global_max / 65536, global_pair

def test1_fold_comparison():
    print("=" * 70)
    print("TEST 1: Fold Comparison DDT (Current vs Nibble-Swap)")
    print("=" * 70)
    t0 = time.time()

    current = compute_mdp_profile(mfr_8, rot=3)
    proposed = compute_mdp_profile(mfr_8_byteswap, rot=3)

    # Global MDPs
    print("\nComputing global MDPs (all 255 input differences)...")
    curr_global, curr_pair = compute_global_mdp(mfr_8, rot=3)
    prop_global, prop_pair = compute_global_mdp(mfr_8_byteswap, rot=3)

    elapsed = time.time() - t0

    print(f"\nPer-bit MDP comparison (rot=3):\n")
    print(f"{'Bit':>3} | {'Current log2':>13} | {'Proposed log2':>14} | {'Improvement':>11}")
    print(f"{'-'*3}-+-{'-'*13}-+-{'-'*14}-+-{'-'*11}")
    for i in range(8):
        curr_l = current[i][2]
        prop_l = proposed[i][2]
        diff = prop_l - curr_l  # negative = better (lower MDP)
        arrow = "<< BETTER" if diff < -0.1 else (">> WORSE" if diff > 0.1 else "   ~same")
        print(f"  {i} | {curr_l:>+13.3f} | {prop_l:>+14.3f} | {arrow}")

    print(f"\nGlobal MDP (worst over all da!=0, all dy):")
    print(f"  Current:  2^{math.log2(curr_global):.3f}  (da=0x{curr_pair[0]:02X}, dy=0x{curr_pair[1]:02X})")
    print(f"  Proposed: 2^{math.log2(prop_global):.3f}  (da=0x{prop_pair[0]:02X}, dy=0x{prop_pair[1]:02X})")

    # Check rotation invariance for proposed fold
    inv_ok = True
    for rot in [3, 5, 7]:
        p = compute_mdp_profile(mfr_8_byteswap, rot=rot)
        for i in range(8):
            if abs(p[i][2] - proposed[i][2]) > 0.001:
                inv_ok = False

    print(f"\n  Proposed rotation invariance (rot=3,5,7): {'PASS' if inv_ok else 'FAIL'}")
    print(f"  Time: {elapsed:.1f}s")

    RESULTS['test1'] = {
        'current': current,
        'proposed': proposed,
        'curr_global': (curr_global, curr_pair),
        'prop_global': (prop_global, prop_pair),
        'rotation_invariant': inv_ok,
        'time': elapsed,
    }


# ═════════════════════════════════════════════════════════════════
#  TEST 2: Trail Clustering
# ═════════════════════════════════════════════════════════════════

def test2_trail_clustering():
    print("\n" + "=" * 70)
    print("TEST 2: Trail Clustering (1R and 2R quintet)")
    print("=" * 70)
    t0 = time.time()

    rot0, rot1 = 3, 5

    # For each non-zero input difference pattern (in word 'a'),
    # track output difference distribution after 1 quintet.
    # Clustering = many distinct internal trails mapping to same output delta.

    # Exhaustive over 5 words × 8 bits = 40-bit state is infeasible.
    # Instead: fix b,c,d,e = 0 and sweep a through all 256 values
    # for each input difference da in word 'a'.
    # Then check: for each da, how concentrated is the output distribution?

    print("\n1-Round quintet: output difference concentration")
    print(f"  Testing all 255 single-word input diffs (da in word a)")

    # For each da: compute (da_out across all 5 words) for all fixed states
    # We sample: fix b=c=d=e to several values, vary a over 0..255
    cluster_data_1r = []
    num_base_states = 16  # sample 16^4 = 65536 base states... too many
    # Actually: fix b,c,d,e each to a few values. Let's do 4^4 = 256 base states.
    base_vals = [0, 0x55, 0xAA, 0xFF]

    for da in [1, 2, 4, 8, 16, 32, 64, 128, 0x55, 0xAA, 0xFF]:
        output_diffs = Counter()
        total = 0
        for bv in base_vals:
            for cv in base_vals:
                for dv in base_vals:
                    for ev in base_vals:
                        for a in range(256):
                            a2 = a ^ da
                            o1 = quintet_8(a, bv, cv, dv, ev, rot0, rot1)
                            o2 = quintet_8(a2, bv, cv, dv, ev, rot0, rot1)
                            diff = tuple((x ^ y) & 0xFF for x, y in zip(o1, o2))
                            output_diffs[diff] += 1
                            total += 1

        # Clustering metric: if top-1 output diff accounts for > 1/256 of total,
        # there's concentration. Ideal random: ~uniform over 2^40 possibilities.
        top1 = output_diffs.most_common(1)[0]
        top5 = output_diffs.most_common(5)
        n_unique = len(output_diffs)
        top1_frac = top1[1] / total

        cluster_data_1r.append({
            'da': da,
            'total': total,
            'unique_outputs': n_unique,
            'top1_count': top1[1],
            'top1_frac': top1_frac,
            'top1_diff': top1[0],
        })
        print(f"  da=0x{da:02X}: {n_unique:>6} unique diffs, top1={top1_frac:.4f} ({top1[1]}/{total})")

    # 2-Round: chain two quintets (different rots to simulate row+col)
    print(f"\n2-Round (chained quintets): output difference concentration")
    cluster_data_2r = []
    for da in [1, 4, 16, 64, 128, 0xFF]:
        output_diffs = Counter()
        total = 0
        for bv in base_vals:
            for cv in base_vals:
                for dv in base_vals:
                    for ev in base_vals:
                        for a in range(256):
                            a2 = a ^ da
                            # Round 1
                            o1 = quintet_8(a, bv, cv, dv, ev, rot0, rot1)
                            o2 = quintet_8(a2, bv, cv, dv, ev, rot0, rot1)
                            # Round 2 (use outputs as inputs, different rots)
                            r1 = quintet_8(*o1, 5, 7)
                            r2 = quintet_8(*o2, 5, 7)
                            diff = tuple((x ^ y) & 0xFF for x, y in zip(r1, r2))
                            output_diffs[diff] += 1
                            total += 1

        top1 = output_diffs.most_common(1)[0]
        n_unique = len(output_diffs)
        top1_frac = top1[1] / total

        cluster_data_2r.append({
            'da': da,
            'total': total,
            'unique_outputs': n_unique,
            'top1_count': top1[1],
            'top1_frac': top1_frac,
        })
        print(f"  da=0x{da:02X}: {n_unique:>6} unique diffs, top1={top1_frac:.6f} ({top1[1]}/{total})")

    elapsed = time.time() - t0
    print(f"  Time: {elapsed:.1f}s")

    RESULTS['test2'] = {
        'cluster_1r': cluster_data_1r,
        'cluster_2r': cluster_data_2r,
        'time': elapsed,
    }


# ═════════════════════════════════════════════════════════════════
#  TEST 3: MSB Propagation
# ═════════════════════════════════════════════════════════════════

def test3_msb_propagation():
    print("\n" + "=" * 70)
    print("TEST 3: MSB Propagation Through Reduced Rounds")
    print("=" * 70)
    t0 = time.time()

    # Inject da = 0x80 (MSB only) in word 'a',
    # track if output difference has detectable bias after R rounds.
    # Random expectation: each output bit set with probability ~0.5

    da = 0x80  # MSB
    base_vals = [0, 0x55, 0xAA, 0xFF]
    max_rounds = 4

    print(f"\nInput: da=0x80 (MSB only) in word 'a'")
    print(f"Tracking output bit bias over {max_rounds} rounds")
    print(f"Random expectation: each bit set ~50% of the time\n")

    rot_schedule = [(3, 5), (5, 7), (7, 3), (3, 7)]
    msb_data = []

    for nrounds in range(1, max_rounds + 1):
        # Count how often each output bit (across all 5 words) is set in the difference
        bit_counts = [[0] * 8 for _ in range(5)]  # 5 words × 8 bits
        total = 0

        for bv in base_vals:
            for cv in base_vals:
                for dv in base_vals:
                    for ev in base_vals:
                        for a in range(256):
                            a2 = a ^ da
                            s1 = (a, bv, cv, dv, ev)
                            s2 = (a2, bv, cv, dv, ev)

                            for r in range(nrounds):
                                r0, r1 = rot_schedule[r % len(rot_schedule)]
                                s1 = quintet_8(*s1, r0, r1)
                                s2 = quintet_8(*s2, r0, r1)

                            total += 1
                            for w in range(5):
                                diff_w = (s1[w] ^ s2[w]) & 0xFF
                                for bit in range(8):
                                    if diff_w & (1 << bit):
                                        bit_counts[w][bit] += 1

        # Compute bias for each word
        print(f"  {nrounds}R:")
        round_data = {'round': nrounds, 'words': []}
        for w in range(5):
            biases = []
            for bit in range(8):
                freq = bit_counts[w][bit] / total
                bias = abs(freq - 0.5)
                biases.append((bit, freq, bias))
            max_bias = max(b[2] for b in biases)
            worst_bit = max(biases, key=lambda x: x[2])
            status = "RANDOM" if max_bias < 0.05 else ("BIASED" if max_bias < 0.2 else "STRONG BIAS")
            print(f"    word {w}: max_bias={max_bias:.4f} (bit {worst_bit[0]}, freq={worst_bit[1]:.4f}) [{status}]")
            round_data['words'].append({
                'word': w,
                'max_bias': max_bias,
                'worst_bit': worst_bit[0],
                'worst_freq': worst_bit[1],
                'status': status,
            })
        msb_data.append(round_data)

    elapsed = time.time() - t0
    print(f"  Time: {elapsed:.1f}s")

    RESULTS['test3'] = {
        'rounds': msb_data,
        'time': elapsed,
    }


# ═════════════════════════════════════════════════════════════════
#  TEST 4: Algebraic Degree
# ═════════════════════════════════════════════════════════════════

def compute_anf_degree(truth_table, n_vars):
    """Compute algebraic degree of a Boolean function via Möbius transform.
    truth_table: list of 2^n_vars bits (0/1).
    Returns: algebraic degree (max Hamming weight of nonzero monomial)."""
    N = 1 << n_vars
    # Möbius transform (ANF coefficients)
    anf = list(truth_table)
    for i in range(n_vars):
        step = 1 << i
        for j in range(N):
            if j & step:
                anf[j] ^= anf[j ^ step]

    # Find max Hamming weight among nonzero ANF coefficients
    max_deg = 0
    for idx in range(N):
        if anf[idx]:
            hw = bin(idx).count('1')
            if hw > max_deg:
                max_deg = hw
    return max_deg

def test4_algebraic_degree():
    print("\n" + "=" * 70)
    print("TEST 4: Algebraic Degree of MFR Output Bits")
    print("=" * 70)
    t0 = time.time()

    # MFR has 2 inputs: a (8-bit), b (8-bit) = 16 input bits
    # 8 output bits. Compute degree of each output bit.
    # Then chain through quintet rounds and track degree growth.

    # For standalone MFR:
    n_vars = 16  # a(8) + b(8)
    N = 1 << n_vars  # 65536

    print(f"\nStandalone MFR (16 input bits, 8 output bits, rot=3):")
    mfr_degrees = []
    for out_bit in range(8):
        tt = [0] * N
        for ab in range(N):
            a = ab >> 8
            b = ab & 0xFF
            out = mfr_8(a, b, 3)
            tt[ab] = (out >> out_bit) & 1
        deg = compute_anf_degree(tt, n_vars)
        mfr_degrees.append(deg)
        print(f"  Output bit {out_bit}: degree {deg} / {n_vars}")

    print(f"\nProposed nibble-swap MFR (same inputs, rot=3):")
    mfr_ns_degrees = []
    for out_bit in range(8):
        tt = [0] * N
        for ab in range(N):
            a = ab >> 8
            b = ab & 0xFF
            out = mfr_8_byteswap(a, b, 3)
            tt[ab] = (out >> out_bit) & 1
        deg = compute_anf_degree(tt, n_vars)
        mfr_ns_degrees.append(deg)
        print(f"  Output bit {out_bit}: degree {deg} / {n_vars}")

    # For quintet: 5 × 8 = 40 input bits → 2^40 truth table is infeasible.
    # Instead: fix 3 words, use 2 words as inputs (16 bits total).
    # This measures degree of 1R quintet restricted to (a, b) inputs.
    print(f"\n1R Quintet (a,b variable, c=d=e=0, rot=3,5):")
    print(f"  (16 input bits from a,b → 40 output bits across 5 words)")
    q_degrees = {}
    for w in range(5):
        for out_bit in range(8):
            tt = [0] * N
            for ab in range(N):
                a = ab >> 8
                b = ab & 0xFF
                result = quintet_8(a, b, 0, 0, 0, 3, 5)
                tt[ab] = (result[w] >> out_bit) & 1
            deg = compute_anf_degree(tt, n_vars)
            q_degrees[(w, out_bit)] = deg

    for w in range(5):
        degs = [q_degrees[(w, bit)] for bit in range(8)]
        print(f"  word {w}: degrees = {degs}, max = {max(degs)}")

    # 2R quintet
    print(f"\n2R Quintet (a,b variable, c=d=e=0):")
    q2_degrees = {}
    for w in range(5):
        for out_bit in range(8):
            tt = [0] * N
            for ab in range(N):
                a = ab >> 8
                b = ab & 0xFF
                r1 = quintet_8(a, b, 0, 0, 0, 3, 5)
                r2 = quintet_8(*r1, 5, 7)
                tt[ab] = (r2[w] >> out_bit) & 1
            deg = compute_anf_degree(tt, n_vars)
            q2_degrees[(w, out_bit)] = deg

    for w in range(5):
        degs = [q2_degrees[(w, bit)] for bit in range(8)]
        print(f"  word {w}: degrees = {degs}, max = {max(degs)}")

    elapsed = time.time() - t0
    print(f"  Time: {elapsed:.1f}s")

    RESULTS['test4'] = {
        'mfr_current': mfr_degrees,
        'mfr_proposed': mfr_ns_degrees,
        'quintet_1r': {w: [q_degrees[(w, b)] for b in range(8)] for w in range(5)},
        'quintet_2r': {w: [q2_degrees[(w, b)] for b in range(8)] for w in range(5)},
        'max_possible': n_vars,
        'time': elapsed,
    }


# ═════════════════════════════════════════════════════════════════
#  TEST 5: Reduced-Round Distinguisher (Chi-squared)
# ═════════════════════════════════════════════════════════════════

def test5_distinguisher():
    print("\n" + "=" * 70)
    print("TEST 5: Reduced-Round Distinguisher (chi-squared)")
    print("=" * 70)
    t0 = time.time()

    # For R rounds of quintet:
    # 1. Generate N random (a,b,c,d,e) pairs
    # 2. For each, inject known da in word 'a'
    # 3. Collect output difference distribution (truncated to word 'a')
    # 4. Chi-squared test against uniform distribution
    # If chi-sq is high → distinguishable from random → bad
    # If chi-sq ~ expected → indistinguishable → good

    import random
    random.seed(0x4B4B_2026)

    N_SAMPLES = 2**18  # 262144 samples
    max_rounds = 4
    rot_schedule = [(3, 5), (5, 7), (7, 3), (3, 7)]

    # Test with da = 1 (single bit) and da = 0x80 (MSB)
    test_diffs = [0x01, 0x80, 0x55]

    print(f"\nSamples per test: {N_SAMPLES}")
    print(f"Output: truncated to word 'a' (8-bit = 256 bins)")
    print(f"Expected chi-sq for 256 bins ≈ 255 (df=255)")
    print(f"Critical value (p=0.001): ~310\n")

    dist_data = []

    for da in test_diffs:
        print(f"  da=0x{da:02X}:")
        for nrounds in range(1, max_rounds + 1):
            bins = [0] * 256
            for _ in range(N_SAMPLES):
                a = random.randint(0, 255)
                b = random.randint(0, 255)
                c = random.randint(0, 255)
                d = random.randint(0, 255)
                e = random.randint(0, 255)

                s1 = (a, b, c, d, e)
                s2 = (a ^ da, b, c, d, e)

                for r in range(nrounds):
                    r0, r1 = rot_schedule[r % len(rot_schedule)]
                    s1 = quintet_8(*s1, r0, r1)
                    s2 = quintet_8(*s2, r0, r1)

                diff_a = (s1[0] ^ s2[0]) & 0xFF
                bins[diff_a] += 1

            # Chi-squared: sum((observed - expected)^2 / expected)
            expected = N_SAMPLES / 256
            chi_sq = sum((obs - expected) ** 2 / expected for obs in bins)
            # Also check: is the zero-difference bin anomalously high?
            zero_bin = bins[0]
            zero_expected = expected

            verdict = "PASS (random)" if chi_sq < 350 else "FAIL (distinguishable)"
            if chi_sq > 1000:
                verdict = "FAIL (strongly distinguishable)"

            print(f"    {nrounds}R: chi_sq={chi_sq:>10.1f}  zero_bin={zero_bin:>5} (exp={expected:.0f})  [{verdict}]")

            dist_data.append({
                'da': da,
                'rounds': nrounds,
                'chi_sq': chi_sq,
                'zero_bin': zero_bin,
                'expected': expected,
                'verdict': verdict,
            })

    elapsed = time.time() - t0
    print(f"  Time: {elapsed:.1f}s")

    RESULTS['test5'] = {
        'n_samples': N_SAMPLES,
        'data': dist_data,
        'time': elapsed,
    }


# ═════════════════════════════════════════════════════════════════
#  Main: run all tests
# ═════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("KK Attack Validation Suite")
    print("=" * 70)
    total_t0 = time.time()

    test1_fold_comparison()
    test2_trail_clustering()
    test3_msb_propagation()
    test4_algebraic_degree()
    test5_distinguisher()

    total_elapsed = time.time() - total_t0
    print("\n" + "=" * 70)
    print(f"ALL TESTS COMPLETE — Total time: {total_elapsed:.1f}s")
    print("=" * 70)
