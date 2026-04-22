"""
PA #16 — ElGamal Public-Key Cryptosystem
==========================================
No-library rule: only Python builtins + PA#11 DH group infrastructure.

Key generation:
  x  ← Zq            (private key)
  h  = g^x mod p      (public key)

Encryption (randomised):
  r  ← Zq
  C  = (c1, c2) = (g^r mod p, m·h^r mod p)

Decryption:
  m  = c2 · c1^(-x) mod p   = c2 · (g^(rx))^(-1) mod p

IND-CPA security: under DDH assumption the ciphertext is
computationally indistinguishable from random.

Malleability (not IND-CCA):
  (c1, λ·c2) decrypts to λ·m  — ciphertext can be scaled without detection.

Exports (PA#17 interface)
--------------------------
elgamal_keygen(p, q, g)         -> (x, h)
elgamal_enc(p, q, g, h, m)     -> (c1, c2)
elgamal_dec(p, x, c1, c2)      -> m
"""

import secrets as _sec
import time

from crypto.pa11_dh import gen_dh_params
from crypto.pa13_miller_rabin import mod_exp
from crypto.pa12_rsa import mod_inverse


# ── Core operations ────────────────────────────────────────────────────────────

def elgamal_keygen(p: int, q: int, g: int) -> tuple[int, int]:
    """
    Sample x ← Zq, compute h = g^x mod p.
    Returns (x, h): x is the private key, h the public key element.
    """
    x = 1 + _sec.randbelow(q - 1)   # x ∈ [1, q-1]
    h = mod_exp(g, x, p)
    return x, h


def elgamal_enc(p: int, q: int, g: int, h: int, m: int) -> tuple[int, int]:
    """
    Randomised ElGamal encryption.
    m must be an element of Z*_p (i.e. 1 ≤ m < p).

    C = (c1, c2) = (g^r mod p,  m · h^r mod p)

    A fresh ephemeral r ← Zq is chosen per encryption, making the scheme
    semantically secure (IND-CPA) under the DDH assumption.
    """
    if not (1 <= m < p):
        raise ValueError(f"Message m={m} must be in [1, p-1]")
    r  = 1 + _sec.randbelow(q - 1)   # ephemeral randomness
    c1 = mod_exp(g, r, p)             # g^r mod p
    c2 = (m * mod_exp(h, r, p)) % p  # m · h^r mod p
    return c1, c2


def elgamal_dec(p: int, x: int, c1: int, c2: int) -> int:
    """
    Decrypt: m = c2 · c1^(-x) mod p.

    c1^x = (g^r)^x = g^(rx) = h^r mod p
    c2 / h^r = (m · h^r) / h^r = m mod p
    """
    s   = mod_exp(c1, x, p)          # s = h^r = g^(rx)
    s_inv = mod_inverse(s, p)        # s^-1 mod p
    return (c2 * s_inv) % p


# ── Malleability attack ────────────────────────────────────────────────────────

def elgamal_malleability(p: int, q: int, g: int, h: int, x: int,
                         m: int, lam: int = 2) -> dict:
    """
    Demonstrate ElGamal malleability (→ not IND-CCA).

    Given ciphertext C = (c1, c2) for m, an adversary who knows λ can produce
    C' = (c1, λ·c2) — which decrypts to λ·m — without knowing the private key x
    or the original message m.

    λ is a public scalar; typically 2 is used for the demonstration.
    """
    c1, c2 = elgamal_enc(p, q, g, h, m)

    # Adversary modifies c2: multiplies by λ (no private key needed)
    c2_prime = (lam * c2) % p

    # Decryption of tampered ciphertext
    m_orig    = elgamal_dec(p, x, c1, c2)
    m_prime   = elgamal_dec(p, x, c1, c2_prime)

    assert m_orig == m, f"Decryption mismatch: {m_orig} != {m}"

    return {
        'message':      m,
        'lambda':       lam,
        'c1':           c1,
        'c2':           c2,
        'c2_prime':     c2_prime,    # tampered
        'm_decrypted':  m_prime,
        'm_expected':   (lam * m) % p,
        'attack_valid': m_prime == (lam * m) % p,
        'explanation': (
            f"Original C = (g^r, m·h^r). Attacker computes C' = (c1, {lam}·c2) = (g^r, {lam}·m·h^r). "
            f"Decrypting C' gives {lam}·m mod p = {m_prime}. "
            f"The adversary changed the plaintext from {m} to {m_prime} "
            f"without knowing x or m — ElGamal is malleable (not CCA-secure)."
        ),
    }


# ── IND-CPA Game ──────────────────────────────────────────────────────────────

def ind_cpa_game(p: int, q: int, g: int, n_rounds: int = 50) -> dict:
    """
    IND-CPA (semantic security) experiment.

    In each round:
      1. Challenger generates a fresh key pair (x, h).
      2. Adversary submits m0, m1 (both in Z*_p).
      3. Challenger flips a coin b ∈ {0,1} and encrypts m_b → C.
      4. Adversary guesses b' ∈ {0,1}.

    We simulate two adversary strategies:
      - Dumb:   always guess 0  → wins ≈ 50% (random chance)
      - Smart:  try to re-encrypt m0 and compare ciphertexts
                 → still ≈ 50% due to fresh r in each encryption (semantic security)

    Under DDH, no PPT adversary wins with probability noticeably > 1/2.
    """
    results = {'rounds': n_rounds, 'strategies': {}}

    for strategy in ('dumb', 'smart'):
        wins = 0
        for _ in range(n_rounds):
            # Fresh keys each round
            x, h = elgamal_keygen(p, q, g)

            # Adversary's two challenge messages (small integers in [2, p-2])
            m0 = 2 + _sec.randbelow(min(1000, p - 3))
            m1 = 2 + _sec.randbelow(min(1000, p - 3))

            # Challenger's coin flip and encryption
            b = _sec.randbelow(2)
            m_b = m0 if b == 0 else m1
            c1, c2 = elgamal_enc(p, q, g, h, m_b)

            # Adversary guesses
            if strategy == 'dumb':
                b_guess = 0   # always 0
            else:
                # "Smart": try to recover m from (c1, c2) by checking m0 vs m1
                # Can't — h^r is unknown (DDH). Just guess based on parity of c2.
                b_guess = 0 if (c2 % 2 == m0 % 2) else 1

            if b_guess == b:
                wins += 1

        results['strategies'][strategy] = {
            'wins': wins,
            'total': n_rounds,
            'win_rate': round(wins / n_rounds, 3),
            'expected': 0.5,
        }

    results['conclusion'] = (
        "Both strategies win ~50% of rounds — indistinguishable from random guessing. "
        "ElGamal is IND-CPA secure under the DDH assumption: ciphertexts hide the plaintext bit b."
    )
    return results


# ── IND-CCA failure demo ──────────────────────────────────────────────────────

def ind_cca_failure(p: int, q: int, g: int) -> dict:
    """
    ElGamal is NOT IND-CCA: the decryption oracle can be exploited.

    IND-CCA2 game:
      Adversary receives challenge ciphertext C* = (c1*, c2*) for m_b.
      Allowed to query decryption oracle on any C ≠ C*.

    Attack: submit C' = (c1*, 2·c2*) to oracle → get 2·m_b mod p.
    Divide by 2 mod p → recover m_b → guess b = 0 or 1 exactly.

    returns: adversary's win (always True here) + intermediate values.
    """
    x, h = elgamal_keygen(p, q, g)

    m0 = 2 + _sec.randbelow(min(100, p - 3))
    m1 = m0 + 1  # distinct messages (keep small for clarity)
    while m1 >= p:
        m1 = 2 + _sec.randbelow(min(100, p - 3))

    # Challenger flips coin
    b   = _sec.randbelow(2)
    m_b = m0 if b == 0 else m1

    # Challenge ciphertext
    c1_star, c2_star = elgamal_enc(p, q, g, h, m_b)

    # Adversary's malleability query: (c1*, 2·c2*) ≠ (c1*, c2*)
    c2_tampered = (2 * c2_star) % p
    two_mb = elgamal_dec(p, x, c1_star, c2_tampered)   # = 2·m_b mod p

    # Recover m_b: compute two_mb · 2^(-1) mod p
    inv2    = mod_inverse(2, p)
    m_b_recovered = (two_mb * inv2) % p

    b_guess = 0 if m_b_recovered == m0 else 1
    won     = (b_guess == b)

    return {
        'm0': m0, 'm1': m1, 'b': b, 'm_b': m_b,
        'c1_star': c1_star, 'c2_star': c2_star,
        'c2_tampered': c2_tampered,
        'two_mb_from_oracle': two_mb,
        'inv2': inv2,
        'm_b_recovered': m_b_recovered,
        'b_guess': b_guess,
        'won': won,
        'explanation': (
            f"Challenge C* = (g^r, m_b·h^r). "
            f"Adversary queries C' = (c1*, 2·c2*) ≠ C* → oracle returns 2·m_b = {two_mb}. "
            f"Divide by 2 mod p → m_b = {m_b_recovered}. "
            f"Compare with m0={m0}, m1={m1} → b={b_guess}. "
            f"Win: {won}. ElGamal is NOT IND-CCA secure."
        ),
    }


# ── IND-CPA small-group distinguisher ─────────────────────────────────────────

def ind_cpa_small_group_attack(p: int, q: int, g: int, n_rounds: int = 30) -> dict:
    """
    IND-CPA distinguisher that works when the group order q is tiny (≈ 2^10).

    Strategy: given challenge ciphertext C = (c1, c2):
      1. Brute-force r such that g^r ≡ c1 (mod p)  — feasible for small q.
      2. Recover m = c2 · (h^r)^(-1) mod p.
      3. Compare recovered m with m0 or m1 → guess b deterministically.

    Wins ≈ 100% for 10-bit q; wins ≈ 50% for large q (DLP intractable).
    """
    wins      = 0
    dlp_found = 0
    details   = []
    q_int     = int(q)

    for i in range(n_rounds):
        x, h = elgamal_keygen(p, q, g)
        m0 = 2 + _sec.randbelow(min(100, p - 3))
        m1 = m0 + 1 + _sec.randbelow(3)
        while m1 >= p:
            m1 = 2 + _sec.randbelow(min(100, p - 3))

        b   = _sec.randbelow(2)
        m_b = m0 if b == 0 else m1
        c1, c2 = elgamal_enc(p, q, g, h, m_b)

        # Brute-force: find r with g^r ≡ c1 mod p
        r_found = None
        cur = 1
        for r_try in range(1, q_int + 1):
            cur = (cur * g) % p
            if cur == c1:
                r_found = r_try
                break

        if r_found is not None:
            dlp_found += 1
            hr_inv      = mod_inverse(mod_exp(h, r_found, p), p)
            m_recovered = (c2 * hr_inv) % p
            b_guess     = 0 if m_recovered == m0 else 1
        else:
            m_recovered = None
            b_guess     = _sec.randbelow(2)   # random fallback (shouldn't happen for tiny q)

        won = (b_guess == b)
        if won:
            wins += 1

        if i < 5:
            details.append({
                'round': i + 1, 'b': b,
                'm0': m0, 'm1': m1, 'm_b': m_b,
                'r_found': r_found, 'm_recovered': m_recovered,
                'b_guess': b_guess, 'won': won,
            })

    q_bits   = q_int.bit_length()
    win_rate = wins / n_rounds
    advantage = round(abs(win_rate - 0.5) * 2, 3)

    return {
        'wins':      wins,
        'total':     n_rounds,
        'dlp_found': dlp_found,
        'win_rate':  round(win_rate, 3),
        'advantage': advantage,
        'q_bits':    q_bits,
        'details':   details,
        'conclusion': (
            f"Distinguisher wins {wins}/{n_rounds} rounds ({win_rate*100:.1f}%) by brute-forcing DLP "
            f"(q is only {q_bits}-bit, exhaustive: {q_bits=}). "
            f"Adversary advantage = {advantage} (≈1.0 for tiny q, ≈0.0 for large q). "
            f"ElGamal IND-CPA security BREAKS completely in small groups — DDH is trivially false."
        ),
    }


# ── IND-CCA multi-round win counter ───────────────────────────────────────────

def ind_cca_multi_round(p: int, q: int, g: int, n_rounds: int = 20) -> dict:
    """
    Run the deterministic IND-CCA2 oracle attack for n_rounds rounds.
    Count how many times the adversary wins (should be ~100%).
    Returns per-round detail rows and a summary.
    """
    wins = 0
    rows = []

    for i in range(n_rounds):
        r  = ind_cca_failure(p, q, g)
        if r['won']:
            wins += 1
        rows.append({
            'round':   i + 1,
            'm0':      r['m0'],    'm1': r['m1'],
            'b':       r['b'],     'b_guess': r['b_guess'],
            'm_b':     r['m_b'],   'm_recovered': r['m_b_recovered'],
            'won':     r['won'],
        })

    win_rate = wins / n_rounds
    return {
        'wins':      wins,
        'total':     n_rounds,
        'win_rate':  round(win_rate, 3),
        'rows':      rows,
        'conclusion': (
            f"Adversary wins {wins}/{n_rounds} rounds ({win_rate*100:.1f}%). "
            f"{'Attack is deterministic — wins every round.' if wins == n_rounds else f'Won {wins}/{n_rounds} — near-perfect.'} "
            f"ElGamal is definitively NOT IND-CCA2 secure."
        ),
    }


# ── Full demo helper ──────────────────────────────────────────────────────────

def elgamal_full_demo(bits: int = 32, message_int: int | None = None) -> dict:
    """Generate params, key, encrypt, decrypt — return the full transcript."""
    t0      = time.perf_counter()
    params  = gen_dh_params(bits)
    p, q, g = params['p'], params['q'], params['g']
    keygen_ms = (time.perf_counter() - t0) * 1000

    x, h = elgamal_keygen(p, q, g)

    # Default message: a random element
    if message_int is None:
        m = 2 + _sec.randbelow(min(10000, p - 3))
    else:
        m = int(message_int) % (p - 1) + 1   # keep in [1, p-1]

    t_enc = time.perf_counter()
    c1, c2 = elgamal_enc(p, q, g, h, m)
    enc_ms = (time.perf_counter() - t_enc) * 1000

    t_dec = time.perf_counter()
    m_rec = elgamal_dec(p, x, c1, c2)
    dec_ms = (time.perf_counter() - t_dec) * 1000

    return {
        'params': {'p': p, 'q': q, 'g': g, 'bits': bits},
        'private_x': x,
        'public_h': h,
        'message': m,
        'c1': c1, 'c2': c2,
        'decrypted': m_rec,
        'correct': m_rec == m,
        'keygen_ms': round(keygen_ms, 3),
        'enc_ms':    round(enc_ms,    3),
        'dec_ms':    round(dec_ms,    3),
    }
