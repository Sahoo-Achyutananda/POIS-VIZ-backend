"""
PA #13 — Miller-Rabin Primality Testing
========================================
No-Library rule: only Python builtins (secrets, math, time).

Key implementation requirements (from assignment):
  1. Miller-Rabin test with own square-and-multiply modular exponentiation.
  2. gen_prime(bits, k=40) — random odd b-bit candidate loop.
  3. Carmichael number demo (561 vs Fermat vs MR).
  4. Performance benchmark (512, 1024, 2048 bits).
  5. Exported is_prime(n) / gen_prime(bits) interface for PA#11, PA#12.

Exports
-------
mod_exp(base, exp, mod)   -> int   (square-and-multiply)
miller_rabin(n, k)        -> "PROBABLY_PRIME" | "COMPOSITE"
gen_prime(bits, k)        -> (prime_int, candidates_tried, elapsed_ms)
is_prime(n)               -> bool
carmichael_demo()         -> dict
prime_generation_benchmark(bits_list, trials) -> list[dict]
"""

import secrets
import math
import time


# ── Square-and-Multiply Modular Exponentiation ─────────────────────────────────

def mod_exp(base: int, exp: int, mod: int) -> int:
    """
    Square-and-multiply modular exponentiation.
    Computes base^exp mod mod using the binary method.
    Required by assignment — no pow() builtin.
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:               # if current bit is 1, multiply
            result = (result * base) % mod
        exp >>= 1                 # shift right (next bit)
        base = (base * base) % mod  # square
    return result


# ── Core Algorithm ─────────────────────────────────────────────────────────────

def _write_n_minus_1(n: int):
    """Write n-1 = 2^s * d with d odd.  Returns (s, d)."""
    s = 0
    d = n - 1
    while d % 2 == 0:
        d >>= 1
        s += 1
    return s, d


def miller_rabin_trace(n: int, k: int = 40):
    """
    Full Miller-Rabin test with per-round witness trace.

    Returns
    -------
    {
      "n": int,
      "k": int,
      "result": "PROBABLY_PRIME" | "COMPOSITE",
      "s": int,
      "d": int,
      "rounds": [
        {
          "i": int,
          "a": int,
          "x_init": int,          # a^d mod n
          "x_history": [int, ...],
          "verdict": "PROBABLY_PRIME" | "COMPOSITE",
        }
      ]
    }
    """
    if n < 2:
        return {"n": n, "k": k, "result": "COMPOSITE", "s": 0, "d": 0, "rounds": []}
    if n == 2 or n == 3:
        return {"n": n, "k": k, "result": "PROBABLY_PRIME", "s": 0, "d": n - 1, "rounds": []}
    if n % 2 == 0:
        return {"n": n, "k": k, "result": "COMPOSITE", "s": 0, "d": 0, "rounds": []}

    s, d = _write_n_minus_1(n)
    rounds = []
    overall = "PROBABLY_PRIME"

    for i in range(k):
        a = 2 + secrets.randbelow(n - 3)  # a in [2, n-2]
        x = mod_exp(a, d, n)              # use our square-and-multiply
        x_history = [x]
        round_verdict = "PROBABLY_PRIME"

        if x == 1 or x == n - 1:
            # passes this witness — continue
            pass
        else:
            composite_flag = True
            for _ in range(s - 1):
                x = mod_exp(x, 2, n)  # square via our mod_exp
                x_history.append(x)
                if x == n - 1:
                    composite_flag = False
                    break
            if composite_flag:
                round_verdict = "COMPOSITE"
                overall = "COMPOSITE"

        rounds.append({
            "i": i + 1,
            "a": a,
            "x_init": x_history[0],
            "x_history": x_history,
            "verdict": round_verdict,
        })

        if overall == "COMPOSITE":
            # early exit — no need for more rounds
            break

    return {
        "n": n,
        "k": k,
        "result": overall,
        "s": s,
        "d": d,
        "rounds": rounds,
    }


def miller_rabin(n: int, k: int = 40) -> str:
    """Lightweight version returning just the verdict string."""
    return miller_rabin_trace(n, k)["result"]


def is_prime(n: int, k: int = 40) -> bool:
    """Boolean wrapper used by PA#11, PA#12."""
    return miller_rabin(n, k) == "PROBABLY_PRIME"


# ── Prime Generation ──────────────────────────────────────────────────────────

def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of the given bit length.
    Repeatedly samples a random odd b-bit integer and tests it
    with Miller-Rabin (k rounds) until a probable prime is found.
    Sanity-verified by the caller with 100 additional MR rounds.

    Returns (prime_int, candidates_tried, elapsed_ms).
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")

    candidates_tried = 0
    t0 = time.perf_counter()

    while True:
        # random b-bit odd integer with the MSB set (ensures exact bit length)
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1))   # set MSB so it is exactly `bits` bits
        n |= 1                    # set LSB so it is always odd
        candidates_tried += 1
        if miller_rabin(n, k) == "PROBABLY_PRIME":
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return n, candidates_tried, elapsed_ms


# ── Sanity Check – 100 MR Rounds on the SAME prime ──────────────────────────

def sanity_check_mr(prime: int, sanity_rounds: int = 100) -> dict:
    """
    Assignment requirement: the output of gen_prime (found with k=40) must pass
    100 rounds of Miller-Rabin as a sanity check.

    Takes the *already-generated* prime and runs miller_rabin_trace on it with
    sanity_rounds=100.  Returns per-round verdicts so the UI can show the trace.
    """
    t0 = time.perf_counter()
    trace = miller_rabin_trace(prime, k=sanity_rounds)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    passed_rounds = sum(1 for r in trace["rounds"] if r["verdict"] == "PROBABLY_PRIME")
    failed_rounds = [r["i"] for r in trace["rounds"] if r["verdict"] == "COMPOSITE"]

    return {
        "prime": str(prime),
        "sanity_rounds": sanity_rounds,
        "generation_rounds": 40,
        "overall": trace["result"],
        "passed_rounds": passed_rounds,
        "failed_rounds": failed_rounds,
        "all_passed": trace["result"] == "PROBABLY_PRIME",
        "time_ms": round(elapsed_ms, 3),
        "s": trace["s"],
        "d": str(trace["d"]),
        # All rounds with full data — same shape as miller_rabin_trace
        "rounds": [
            {
                "i": r["i"],
                "a": str(r["a"]),
                "x_init": str(r["x_init"]),
                "x_history": [str(x) for x in r["x_history"]],
                "verdict": r["verdict"],
            }
            for r in trace["rounds"]
        ],
    }


# ── Carmichael Number Demo ────────────────────────────────────────────────────

def _fermat_test(n: int, a: int) -> bool:
    """Naive Fermat test: returns True if a^(n-1) ≡ 1 (mod n)."""
    return pow(a, n - 1, n) == 1


def carmichael_demo(n: int = 561, k: int = 40) -> dict:
    """
    Show that 561 passes all Fermat witnesses but is caught by Miller-Rabin.
    Returns detailed comparison data.
    """
    # Fermat: test all bases 2 .. n-2 (or first 10 for brevity in UI)
    fermat_witnesses = []
    fermat_sample_bases = list(range(2, min(20, n - 1)))
    fermat_all_pass = True
    for a in fermat_sample_bases:
        if math.gcd(a, n) == 1:
            passes = _fermat_test(n, a)
            fermat_witnesses.append({"a": a, "result": "passes" if passes else "fails"})
            if not passes:
                fermat_all_pass = False

    # Factorisation
    factors = _factorize(n)
    is_carmichael = _is_carmichael(n, factors)

    # Miller-Rabin trace (use small k for display)
    mr_result = miller_rabin_trace(n, k=min(k, 20))

    return {
        "n": n,
        "factors": factors,
        "is_carmichael": is_carmichael,
        "fermat_all_pass": fermat_all_pass,
        "fermat_witnesses_sample": fermat_witnesses[:12],
        "miller_rabin_result": mr_result["result"],
        "miller_rabin_rounds": mr_result["rounds"][:8],
        "s": mr_result["s"],
        "d": mr_result["d"],
        "message": (
            f"{n} is a Carmichael number: passes ALL Fermat witnesses but "
            f"Miller-Rabin correctly returns {mr_result['result']}."
        ),
    }


def _factorize(n: int) -> list:
    """Trial-division factorization (small n only)."""
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def _is_carmichael(n: int, factors: list) -> bool:
    """Korselt's criterion: n is Carmichael iff n is square-free and (p-1)|(n-1) for all prime p|n."""
    from collections import Counter
    if len(factors) < 3:
        return False
    c = Counter(factors)
    if any(v > 1 for v in c.values()):
        return False  # not square-free
    for p in c:
        if (n - 1) % (p - 1) != 0:
            return False
    return True


# ── Performance Benchmark ─────────────────────────────────────────────────────

def prime_generation_benchmark(bits_list=None, trials: int = 3, k: int = 40) -> list:
    """
    Performance benchmark: for each bit-size in bits_list, generate `trials`
    probable primes and report average candidates sampled and average time.

    Also computes the theoretical O(ln n) = O(bits × ln 2) candidates predicted
    by the Prime Number Theorem, so the student can compare empirical vs theory.

    Note on 2048-bit timing:
      Each MR round on a 2048-bit number involves a modular exponentiation of a
      2048-bit base to a ~2048-bit exponent. Python's C-level bignum keeps each
      round to a few ms, and ln(2^2048) ≈ 1420 candidates on average, so expect
      total wall-time of a few minutes for trials=3 at k=40.
    """
    if bits_list is None:
        bits_list = [512, 1024, 2048]

    results = []
    for bits in bits_list:
        candidate_counts = []
        times_ms = []
        for _ in range(trials):
            _, count, ms = gen_prime(bits, k=k)
            candidate_counts.append(count)
            times_ms.append(ms)

        avg_candidates = sum(candidate_counts) / len(candidate_counts)
        avg_ms = sum(times_ms) / len(times_ms)
        # Prime Number Theorem: fraction of b-bit odd numbers that are prime ≈ 1/ln(2^b)
        # So expected candidates = ln(2^b) = b * ln(2)
        theoretical = bits * math.log(2)

        results.append({
            "bits": bits,
            "trials": trials,
            "avg_candidates": round(avg_candidates, 2),
            "theoretical_candidates": round(theoretical, 2),
            "avg_time_ms": round(avg_ms, 2),
            "min_time_ms": round(min(times_ms), 2),
            "max_time_ms": round(max(times_ms), 2),
            "total_time_ms": round(sum(times_ms), 2),
        })

    return results
