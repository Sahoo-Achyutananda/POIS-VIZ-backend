"""
PA #11 — Diffie-Hellman Key Exchange (SKE)
==========================================
No-Library rule: only Python builtins (secrets, math).
Uses PA #13 miller_rabin / gen_prime for safe-prime generation.

Protocol
--------
Public params: safe prime p = 2q+1, generator g of the prime-order subgroup Z*_p of order q.

  Alice: a ← Zq,  sends A = g^a mod p
  Bob:   b ← Zq,  sends B = g^b mod p
  Shared secret K = g^(ab) mod p

Exports
-------
gen_dh_params(bits)          -> dict  {p, q, g}
dh_alice_step1(p, q, g)      -> (a, A)   private exponent + public value
dh_bob_step1(p, q, g)        -> (b, B)
dh_alice_step2(B, a, p)      -> K
dh_bob_step2(A, b, p)        -> K
mitm_demo(p, q, g)           -> dict  (Eve intercepts, shows both secrets)
cdh_brute_force(g, A, B, p, q) -> dict  (time to recover secret by BSGS/brute)
"""

import secrets
import math
import time

from crypto.pa13_miller_rabin import gen_prime, miller_rabin, mod_exp


# ── Safe-prime generation ───────────────────────────────────────────────────────

def _find_generator(p: int, q: int) -> int:
    """
    Find a generator g of the prime-order subgroup of Z*_p of order q.
    For a safe prime p = 2q+1, any element h ∈ {2,…,p-2} with h ≠ 1 and
    h^2 ≠ 1 mod p is a generator of the order-q subgroup.
    We use g = h^2 mod p to ensure we land in the subgroup of order q.
    """
    while True:
        h = 2 + secrets.randbelow(p - 3)   # h in [2, p-2]
        g = mod_exp(h, 2, p)               # g = h^2 mod p; order divides q
        if g != 1:
            return g


def gen_dh_params(bits: int = 32) -> dict:
    """
    Generate safe-prime DH group parameters: p = 2q+1 (both prime), g a
    generator of the prime-order subgroup of Z*_p of order q.

    Uses PA #13's gen_prime to find q, then checks p = 2q+1.

    Returns {'p': int, 'q': int, 'g': int, 'bits': int, 'time_ms': float}
    """
    t0 = time.perf_counter()

    while True:
        # Try to find a Sophie Germain prime q such that p = 2q+1 is also prime
        q_candidate, _, _ = gen_prime(bits - 1, k=40)   # q is (bits-1)-bit prime
        p_candidate = 2 * q_candidate + 1
        if miller_rabin(p_candidate, k=40) == "PROBABLY_PRIME":
            p, q = p_candidate, q_candidate
            break

    g = _find_generator(p, q)
    elapsed = (time.perf_counter() - t0) * 1000

    return {
        "p": p,
        "q": q,
        "g": g,
        "bits": p.bit_length(),
        "time_ms": round(elapsed, 3),
    }


# ── DH Protocol Steps ──────────────────────────────────────────────────────────

def dh_alice_step1(p: int, q: int, g: int) -> tuple[int, int]:
    """Alice samples a ← Zq, computes A = g^a mod p. Returns (a, A)."""
    a = 1 + secrets.randbelow(q - 1)     # a in [1, q-1]
    A = mod_exp(g, a, p)
    return a, A


def dh_bob_step1(p: int, q: int, g: int) -> tuple[int, int]:
    """Bob samples b ← Zq, computes B = g^b mod p. Returns (b, B)."""
    b = 1 + secrets.randbelow(q - 1)
    B = mod_exp(g, b, p)
    return b, B


def dh_alice_step2(B: int, a: int, p: int) -> int:
    """Alice computes K = B^a mod p = g^(ab) mod p."""
    return mod_exp(B, a, p)


def dh_bob_step2(A: int, b: int, p: int) -> int:
    """Bob computes K = A^b mod p = g^(ab) mod p."""
    return mod_exp(A, b, p)


def run_dh_exchange(p: int, q: int, g: int,
                    a: int | None = None,
                    b: int | None = None) -> dict:
    """
    Run a full DH exchange. If a/b are provided (as ints), use them;
    otherwise generate random ones.
    Returns full protocol transcript.
    """
    if a is None or a == 0:
        a_val, A = dh_alice_step1(p, q, g)
    else:
        a_val = int(a) % q or 1
        A = mod_exp(g, a_val, p)

    if b is None or b == 0:
        b_val, B = dh_bob_step1(p, q, g)
    else:
        b_val = int(b) % q or 1
        B = mod_exp(g, b_val, p)

    K_alice = dh_alice_step2(B, a_val, p)
    K_bob   = dh_bob_step2(A, b_val, p)

    return {
        "p": p, "q": q, "g": g,
        "a": a_val, "A": A,
        "b": b_val, "B": B,
        "K_alice": K_alice,
        "K_bob":   K_bob,
        "match": K_alice == K_bob,
    }


# ── MITM Attack Demo ────────────────────────────────────────────────────────────

def mitm_demo(p: int, q: int, g: int,
              a: int | None = None,
              b: int | None = None) -> dict:
    """
    Eve intercepts the exchange and substitutes A' = g^e and B' = g^e.
    She establishes:
        K_AE = g^(ae) (shared with Alice)
        K_BE = g^(be) (shared with Bob)
    Alice and Bob each hold a different key — Eve can read all traffic.
    """
    # Alice's real private exponent
    a_val = (int(a) % q or 1) if a else (1 + secrets.randbelow(q - 1))
    A_real = mod_exp(g, a_val, p)

    # Bob's real private exponent
    b_val = (int(b) % q or 1) if b else (1 + secrets.randbelow(q - 1))
    B_real = mod_exp(g, b_val, p)

    # Eve's exponent
    e = 1 + secrets.randbelow(q - 1)
    E = mod_exp(g, e, p)   # g^e

    # Eve sends A' = g^e to Bob, B' = g^e to Alice
    A_prime = E   # what Alice thinks Bob sent
    B_prime = E   # what Bob thinks Alice sent

    # Alice computes her "shared secret" with who she thinks is Bob
    K_alice = dh_alice_step2(B_prime, a_val, p)   # = g^(ae)
    # Bob computes his "shared secret" with who he thinks is Alice
    K_bob   = dh_bob_step2(A_prime, b_val, p)     # = g^(be)

    # Eve holds both secrets
    K_eve_alice = mod_exp(A_real, e, p)   # = g^(ae) — same as K_alice
    K_eve_bob   = mod_exp(B_real, e, p)   # = g^(be) — same as K_bob

    return {
        "p": p, "q": q, "g": g,
        "alice": {"a": a_val, "A_sent": A_real, "A_received": B_prime, "K": K_alice},
        "bob":   {"b": b_val, "B_sent": B_real, "B_received": A_prime, "K": K_bob},
        "eve":   {"e": e, "E": E, "K_with_alice": K_eve_alice, "K_with_bob": K_eve_bob},
        "alice_bob_match": K_alice == K_bob,  # False under MITM
        "eve_sees_alice": K_eve_alice == K_alice,
        "eve_sees_bob":   K_eve_bob   == K_bob,
    }


# ── CDH Brute-Force Hardness Demo ──────────────────────────────────────────────

def cdh_brute_force(p: int, q: int, g: int,
                    A: int, B: int,
                    max_steps: int = 2 ** 20) -> dict:
    """
    Given g^a mod p and g^b mod p, recover a (discrete log) by brute force,
    then compute g^(ab) mod p.  Only feasible for small q (≤ 2^20).

    Returns time taken, steps tried, and whether the secret was found.
    """
    t0 = time.perf_counter()
    found_a = None
    ga = mod_exp(g, 1, p)     # start: g^1
    for candidate in range(1, min(int(q), max_steps) + 1):
        if ga == A:
            found_a = candidate
            break
        ga = (ga * g) % p

    elapsed = (time.perf_counter() - t0) * 1000

    if found_a is not None:
        K_recovered = mod_exp(B, found_a, p)
        return {
            "found": True,
            "a_recovered": found_a,
            "K_recovered": K_recovered,
            "steps": found_a,
            "time_ms": round(elapsed, 3),
            "q": q,
        }
    else:
        return {
            "found": False,
            "steps": min(int(q), max_steps),
            "time_ms": round(elapsed, 3),
            "q": q,
            "note": f"Not found within {max_steps} steps — q is too large for brute force.",
        }
