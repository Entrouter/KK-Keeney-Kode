"""Run the full MILP analysis: 1,2,3,4,8,16,32 rounds."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analysis.milp_differential import solve_min_active, estimate_probability

mdp = 2.0 ** (-1.415)
time_limits = {1: 30, 2: 30, 3: 60, 4: 120, 8: 600, 16: 1800, 32: 1800}
rounds_list = [1, 2, 3, 4, 8, 16, 32]

results = {}
for nr in rounds_list:
    tl = time_limits.get(nr, 600)
    for mode in ["general", "sponge"]:
        cap = (mode == "sponge")
        t0 = time.time()
        r = solve_min_active(nr, capacity_zero=cap, verbose=False, time_limit=tl)
        elapsed = time.time() - t0
        key = (nr, mode)
        results[key] = r

        best = r["best_found"]
        opt = "OPTIMAL" if r["optimal"] else r["status"]
        pr_str = ""
        if best and best > 0:
            pr_str = f"Pr <= 2^{estimate_probability(best, mdp):.1f}"
        print(f"  {nr:>2}R {mode:>7}: {best or '---':>6}  ({opt})  {pr_str}  [{elapsed:.1f}s]")
        sys.stdout.flush()

print("\n=== SUMMARY TABLE ===")
print(f"{'Rounds':>6}  {'General':>10}  {'Sponge':>10}  {'Gen Pr':>14}  {'Spn Pr':>14}")
print("-" * 62)
for nr in rounds_list:
    g = results.get((nr, "general"), {})
    s = results.get((nr, "sponge"), {})
    g_val = g.get("best_found")
    s_val = s.get("best_found")
    g_str = f"{g_val}{'*' if not g.get('optimal') else ''}" if g_val else "---"
    s_str = f"{s_val}{'*' if not s.get('optimal') else ''}" if s_val else "---"
    g_pr = f"2^{estimate_probability(g_val, mdp):.1f}" if g_val else ""
    s_pr = f"2^{estimate_probability(s_val, mdp):.1f}" if s_val else ""
    print(f"{nr:>6}  {g_str:>10}  {s_str:>10}  {g_pr:>14}  {s_pr:>14}")
print("\n* = time limit reached, true minimum may be higher")
print("Security target: trail probability < 2^(-192)")
