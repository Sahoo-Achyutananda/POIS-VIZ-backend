"""
PA #9 — Birthday Attack Crypto Module

Implements:
  - toy_hash(x_int, n_bits): truncated DLP hash for an integer input
  - naive_birthday_attack(n_bits): dict-based collision finder
  - floyd_birthday_attack(n_bits): tortoise-and-hare cycle finder
  - run_trials(n_bits, num_trials): batch of naive attacks, returns iteration counts
"""
import random
import math


# ── Toy DLP group parameters (reuse from PA8) ────────────────────────────────
P_TOY = 65519
Q_TOY = 32759
G_TOY = 7
H_HAT_TOY = 12345


def _dlp_compress(x_int: int) -> int:
    """
    One-shot DLP compression for a single integer value.
    h(x) = (G_TOY^(x mod Q_TOY) * H_HAT_TOY^(x mod Q_TOY)) mod P_TOY
    Treats the integer as both 'z' and 'm' for a stateless one-block hash.
    """
    z = x_int % Q_TOY
    m = (x_int >> 8) % Q_TOY   # use upper bits as the second exponent
    g_z  = pow(G_TOY,    z, P_TOY)
    h_m  = pow(H_HAT_TOY, m, P_TOY)
    return (g_z * h_m) % P_TOY


def toy_hash(x_int: int, n_bits: int) -> int:
    """
    Hash an integer through the toy DLP group and truncate to n_bits.
    Output domain: [0, 2^n_bits)
    """
    raw = _dlp_compress(x_int)
    mask = (1 << n_bits) - 1
    return raw & mask


def naive_birthday_attack(n_bits: int, max_iter: int = 500_000) -> dict:
    """
    Naive birthday attack: hash random integers, store in dict, detect first repeat.

    Returns dict with:
      found, msg_a, msg_b, hash_val, iterations, birthday_bound, ratio
    """
    modulus = 1 << n_bits            # 2^n_bits
    bound   = math.isqrt(modulus)    # ≈ 2^(n/2)
    seen    = {}                     # hash_val → x_int

    for i in range(1, min(max_iter, modulus * 8) + 1):
        x = random.randrange(0, 2**32)
        h = toy_hash(x, n_bits)

        if h in seen and seen[h] != x:
            return {
                "found":          True,
                "msg_a":          seen[h],
                "msg_b":          x,
                "hash_val":       h,
                "iterations":     i,
                "birthday_bound": bound,
                "ratio":          round(i / bound, 3),
            }
        seen[h] = x

    return {"found": False, "iterations": max_iter, "birthday_bound": bound}


def floyd_birthday_attack(n_bits: int, max_iter: int = 200_000) -> dict:
    """
    Floyd's cycle-finding (tortoise & hare) birthday attack.
    Treats f(x) = toy_hash(x, n_bits) as a function from n-bit outputs to n-bit outputs.

    Phase 1: find cycle meeting point.
    Phase 2: find the pre-images that collide (right before meeting point).
    """
    bound = math.isqrt(1 << n_bits)

    # Random start
    x0 = random.randrange(0, 1 << n_bits)
    f = lambda x: toy_hash(x, n_bits)

    # Phase 1 — detect cycle
    tortoise = f(x0)
    hare     = f(f(x0))
    iters    = 1

    while tortoise != hare and iters < max_iter:
        tortoise = f(tortoise)
        hare     = f(f(hare))
        iters   += 1

    if iters >= max_iter:
        return {"found": False, "iterations": max_iter, "birthday_bound": int(bound)}

    # Phase 2 — locate collision
    # Advance mu from x0 and lam from the meeting point until they map to the same value.
    mu = x0
    lam = tortoise
    
    # Boundary case: if they map to the same value immediately
    if f(mu) == f(lam) and mu != lam:
        return {
            "found":          True,
            "msg_a":          int(mu),
            "msg_b":          int(lam),
            "hash_val":       int(f(mu)),
            "iterations":     iters,
            "birthday_bound": int(bound),
            "ratio":          round(iters / bound, 3),
        }

    phase2_iters = 0
    while f(mu) != f(lam) and phase2_iters < max_iter:
        mu  = f(mu)
        lam = f(lam)
        phase2_iters += 1
        iters += 1

    if f(mu) == f(lam) and mu != lam:
        return {
            "found":          True,
            "msg_a":          int(mu),
            "msg_b":          int(lam),
            "hash_val":       int(f(mu)),
            "iterations":     iters,
            "birthday_bound": int(bound),
            "ratio":          round(iters / bound, 3),
        }

    return {"found": False, "iterations": iters, "birthday_bound": int(bound)}


def run_trials(n_bits: int, num_trials: int = 100) -> dict:
    """
    Run `num_trials` independent naive birthday attacks for `n_bits`.
    Returns counts and statistics for the empirical curve.
    """
    counts = []
    for _ in range(num_trials):
        result = naive_birthday_attack(n_bits)
        counts.append(result.get("iterations", 0))

    mean_count = sum(counts) / len(counts) if counts else 0
    bound      = math.isqrt(1 << n_bits)

    return {
        "n_bits":         n_bits,
        "num_trials":     num_trials,
        "counts":         counts,
        "mean":           round(mean_count, 2),
        "expected_bound": bound,
        "ratio":          round(mean_count / bound, 3) if bound else 0,
    }
