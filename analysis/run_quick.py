"""Quick run: 1-4 round models to get results fast."""
import sys
sys.path.insert(0, ".")
from analysis.milp_differential import solve_min_active, estimate_probability
import math

mdp = 2.0 ** (-1.415)
print("=== QUICK RUN: 1-4 Rounds ===")
print()

for nr in [1, 2, 3, 4]:
    for cap in [False, True]:
        label = "sponge" if cap else "general"
        result = solve_min_active(nr, capacity_zero=cap, verbose=True, time_limit=120)
        bf = result["best_found"]
        if bf and bf > 0:
            log_p = estimate_probability(bf, mdp)
            opt = "OPTIMAL" if result["optimal"] else "best found"
            print(f"  -> {nr}R {label}: {bf} active ({opt}) -> Pr <= 2^{log_p:.1f}")
        print()
        sys.stdout.flush()

print("=== DONE ===")
