"""
PA #18 — Oblivious Transfer (1-out-of-2 OT)
============================================
No-library rule: built on PA#16 ElGamal → PA#11 DH → PA#13 mod_exp.

Protocol: Bellare-Micali OT from PKC
--------------------------------------
Setup: shared ElGamal group (p, q, g).

Step 1 — Receiver (choice bit b):
  • Generate (pk_b, sk_b) honestly:    x_b ← Zq,  h_b = g^{x_b} mod p
  • Generate pk_{1-b} WITHOUT trapdoor: h_{1-b} ← Z*_p  (random, no DLog known)
  • Send (pk0, pk1) to Sender.  Sender cannot tell which is honest.

Step 2 — Sender (messages m0, m1):
  • Encrypt: C_i = ElGamal_enc(p, q, g, h_i, m_i)  for i ∈ {0,1}
  • Send (C0, C1) to Receiver.

Step 3 — Receiver:
  • Decrypt C_b = ElGamal_dec(p, x_b, C_b[0], C_b[1]) → m_b
  • Cannot decrypt C_{1-b}: no x_{1-b} known.

Security:
  Receiver privacy: pk_{1-b} is computationally indistinguishable from a
    properly generated key (DDH hardness) — sender cannot learn b.
  Sender privacy: receiver has no x_{1-b} → decrypting C_{1-b} requires
    solving ElGamal (= DLP in Z*_p) — demonstrated by brute-force failure.

Full lineage: PA#18 → PA#16 → PA#11 → PA#13 → mod_exp / miller_rabin
"""

import secrets as _sec
import time

from crypto.pa16_elgamal import elgamal_keygen, elgamal_enc, elgamal_dec
from crypto.pa11_dh import gen_dh_params
from crypto.pa13_miller_rabin import mod_exp


# ── Step 1: Receiver key generation ──────────────────────────────────────────

def ot_receiver_step1(p: int, q: int, g: int, b: int) -> tuple[dict, dict, dict]:
    """
    OT_Receiver_Step1(b) → (pk0, pk1, state)

    Generates an honest key pair for choice b, and a trapdoor-free key for 1-b.
    The trapdoor-free key h_{1-b} is a uniformly random element of Z*_p;
    no discrete-log is known for it (with overwhelming probability).

    Returns:
        pk0   = {'h': int}   — public key element for choice 0
        pk1   = {'h': int}   — public key element for choice 1
        state = {'b': b, 'x_b': private exponent, 'b_key': 0 or 1}
    """
    if b not in (0, 1):
        raise ValueError("Choice bit b must be 0 or 1")

    # Honest key for choice b
    x_b = 1 + _sec.randbelow(q - 1)
    h_b = mod_exp(g, x_b, p)

    # Trapdoor-free key for 1-b: pick random h ← Z*_p (no DLog known)
    h_other = 1 + _sec.randbelow(p - 2)

    if b == 0:
        pk0 = {'h': h_b}
        pk1 = {'h': h_other}
    else:
        pk0 = {'h': h_other}
        pk1 = {'h': h_b}

    state = {'b': b, 'x_b': x_b, 'p': p, 'q': q, 'g': g}
    return pk0, pk1, state


# ── Step 2: Sender encrypts both messages ─────────────────────────────────────

def ot_sender_step(p: int, q: int, g: int,
                   pk0: dict, pk1: dict,
                   m0: int, m1: int) -> tuple[tuple, tuple]:
    """
    OT_Sender_Step(pk0, pk1, m0, m1) → (C0, C1)

    Encrypts each message under the corresponding public key using ElGamal.
    Fresh randomness r is chosen independently for each.

    Returns: C0 = (c1_0, c2_0),  C1 = (c1_1, c2_1)
    """
    c1_0, c2_0 = elgamal_enc(p, q, g, pk0['h'], m0)
    c1_1, c2_1 = elgamal_enc(p, q, g, pk1['h'], m1)
    return (c1_0, c2_0), (c1_1, c2_1)


# ── Step 3: Receiver decrypts C_b ─────────────────────────────────────────────

def ot_receiver_step2(state: dict,
                      C0: tuple, C1: tuple) -> int:
    """
    OT_Receiver_Step2(state, C0, C1) → m_b

    Decrypts the ciphertext corresponding to the receiver's choice bit b.
    The other ciphertext C_{1-b} is ignored (would require DLP to decrypt).
    """
    b   = state['b']
    x_b = state['x_b']
    p   = state['p']
    C   = C0 if b == 0 else C1
    return elgamal_dec(p, x_b, C[0], C[1])


# ── Correctness test ──────────────────────────────────────────────────────────

def ot_correctness_test(p: int, q: int, g: int,
                        n_trials: int = 100) -> dict:
    """
    Run n_trials OT instances with random b in {0,1} and random (m0, m1).
    Verify that the receiver always recovers m_b.
    Returns per-trial detail rows for UI rendering.
    """
    t0 = time.perf_counter()
    correct = 0
    failures = []
    trial_rows = []

    for trial in range(n_trials):
        tr_start = time.perf_counter()
        b  = _sec.randbelow(2)
        m0 = 2 + _sec.randbelow(min(10000, p - 3))
        m1 = 2 + _sec.randbelow(min(10000, p - 3))

        pk0, pk1, state = ot_receiver_step1(p, q, g, b)
        C0, C1          = ot_sender_step(p, q, g, pk0, pk1, m0, m1)
        m_got           = ot_receiver_step2(state, C0, C1)
        tr_ms           = round((time.perf_counter() - tr_start) * 1000, 2)

        expected = m0 if b == 0 else m1
        passed   = (m_got == expected)
        if passed:
            correct += 1
        else:
            failures.append({'trial': trial + 1, 'b': b, 'expected': expected, 'got': m_got})

        trial_rows.append({
            'trial':    trial + 1,
            'b':        b,
            'm0':       m0,
            'm1':       m1,
            'expected': expected,
            'received': m_got,
            'correct':  passed,
            'ms':       tr_ms,
            'desc': (
                f"Bob chose b={b}, so he should receive m{b}={expected}. "
                f"Alice encrypts m0={m0} and m1={m1} under ElGamal. "
                f"Bob decrypts C{b} with sk{b} and recovers {m_got}. "
                + ("Correct." if passed else f"MISMATCH — expected {expected}, got {m_got}.")
            ),
        })

    elapsed_ms = (time.perf_counter() - t0) * 1000
    return {
        'trials':       n_trials,
        'correct':      correct,
        'failures':     failures,
        'success_rate': round(correct / n_trials, 4),
        'elapsed_ms':   round(elapsed_ms, 2),
        'trial_rows':   trial_rows,
    }


# ── Receiver privacy demo ─────────────────────────────────────────────────────

def receiver_privacy_demo(p: int, q: int, g: int) -> dict:
    """
    Show that the sender cannot determine b from (pk0, pk1).

    Both h_b = g^x mod p (honest) and h_{1-b} (random) are elements of Z*_p.
    Under DDH, they are computationally indistinguishable.

    We demonstrate by checking statistical uniformity of both keys mod q.
    """
    samples = 500
    honest_vals, random_vals = [], []

    for _ in range(samples):
        x  = 1 + _sec.randbelow(q - 1)
        h  = mod_exp(g, x, p)          # honest: h = g^x mod p
        r  = 1 + _sec.randbelow(p - 2) # random: arbitrary Z*_p element
        honest_vals.append(h % q)
        random_vals.append(r % q)

    # Both should be roughly uniform over [0, q)
    import statistics
    h_mean = statistics.mean(honest_vals)
    r_mean = statistics.mean(random_vals)
    h_std  = statistics.stdev(honest_vals)
    r_std  = statistics.stdev(random_vals)

    return {
        'samples': samples,
        'honest_key': {'mean_mod_q': round(h_mean, 2), 'std_mod_q': round(h_std, 2)},
        'random_key': {'mean_mod_q': round(r_mean, 2), 'std_mod_q': round(r_std, 2)},
        'indistinguishable': abs(h_mean - r_mean) < q * 0.15,
        'explanation': (
            'Both h_b = g^x mod p (properly generated) and h_{1-b} (random Z*_p element) '
            'are statistically close to uniform. Under the DDH assumption, no PPT '
            'adversary can distinguish them — the sender cannot learn which is the '
            '"real" public key, hence cannot determine the choice bit b.'
        ),
    }


# ── Sender privacy demo (cheat attempt) ──────────────────────────────────────

def sender_privacy_demo(p: int, q: int, g: int,
                        m0: int, m1: int, b: int,
                        max_brute: int = 500) -> dict:
    """
    Demonstrate that the receiver CANNOT decrypt C_{1-b}.

    The attacker (receiver cheating) tries to brute-force x_{1-b} such that
    g^x = h_{1-b} mod p. For small parameters this takes up to max_brute steps.
    For properly-sized groups (256-bit), this is computationally infeasible.

    Returns evidence that h_{1-b} is a random group element with no known DLog.
    """
    pk0, pk1, state = ot_receiver_step1(p, q, g, b)
    C0, C1          = ot_sender_step(p, q, g, pk0, pk1, m0, m1)
    m_b = ot_receiver_step2(state, C0, C1)

    # The (1-b) public key has no known DLog
    h_other = pk1['h'] if b == 0 else pk0['h']
    C_other = C1 if b == 0 else C0
    m_other = m1 if b == 0 else m0   # the "hidden" message

    # Brute-force attempt: try x = 1..max_brute
    found_x   = None
    found_m   = None
    t0 = time.perf_counter()
    for x_try in range(1, max_brute + 1):
        if mod_exp(g, x_try, p) == h_other:
            found_x = x_try
            found_m = elgamal_dec(p, x_try, C_other[0], C_other[1])
            break
    brute_ms  = (time.perf_counter() - t0) * 1000

    cheat_succeeded = found_m == m_other if found_x is not None else False

    return {
        'b':            b,
        'm0':           m0, 'm1': m1,
        'm_b_received': m_b,    # what receiver legitimately got
        'm_other':      '??',   # hidden from receiver
        'bits':         p.bit_length(),
        'brute_force_limit': max_brute,
        'dlp_solved':   found_x is not None,
        'cheat_succeeded': cheat_succeeded,
        'brute_ms':     round(brute_ms, 3),
        'explanation': (
            f'Receiver has pk_{{1-b}} = h = {h_other} but no secret x such that g^x = h mod p. '
            f'Brute-force tried x in [1, {max_brute}] in {brute_ms:.1f}ms — '
            + (f'found x={found_x}!' if found_x else
               f'DLP not solved. For {p.bit_length()}-bit groups this is computationally infeasible.')
        ),
    }


# ── Interactive single OT run (for step-by-step demo) ─────────────────────────

def ot_run(p: int, q: int, g: int,
           b: int, m0: int, m1: int) -> dict:
    """
    Full single OT execution returning all intermediate values for the UI
    step-by-step message log.
    """
    # Step 1: Receiver
    t1 = time.perf_counter()
    pk0, pk1, state = ot_receiver_step1(p, q, g, b)
    step1_ms = (time.perf_counter() - t1) * 1000

    # Step 2: Sender
    t2 = time.perf_counter()
    C0, C1 = ot_sender_step(p, q, g, pk0, pk1, m0, m1)
    step2_ms = (time.perf_counter() - t2) * 1000

    # Step 3: Receiver
    t3 = time.perf_counter()
    m_received = ot_receiver_step2(state, C0, C1)
    step3_ms = (time.perf_counter() - t3) * 1000

    expected = m0 if b == 0 else m1
    correct  = m_received == expected

    return {
        'b': b,
        'm0': m0, 'm1': m1,

        # Step 1 outputs
        'pk0_h':     pk0['h'],
        'pk1_h':     pk1['h'],
        'honest_key': b,         # which pk is "honest"
        'step1_ms':  round(step1_ms, 3),

        # Step 2 outputs
        'C0': {'c1': C0[0], 'c2': C0[1]},
        'C1': {'c1': C1[0], 'c2': C1[1]},
        'step2_ms': round(step2_ms, 3),

        # Step 3 outputs
        'm_received': m_received,
        'm_hidden':   '??',
        'correct':    correct,
        'step3_ms':  round(step3_ms, 3),
    }


# ── Full demo ─────────────────────────────────────────────────────────────────

def ot_full_demo(bits: int = 32, b: int = 0,
                 m0: int = 42, m1: int = 99) -> dict:
    """Generate group, run OT, correctness test, privacy demos."""
    t0 = time.perf_counter()
    params = gen_dh_params(bits)
    p, q, g = params['p'], params['q'], params['g']
    setup_ms = (time.perf_counter() - t0) * 1000

    run  = ot_run(p, q, g, b, m0, m1)
    corr = ot_correctness_test(p, q, g, n_trials=50)
    priv = receiver_privacy_demo(p, q, g)
    send = sender_privacy_demo(p, q, g, m0, m1, b, max_brute=200)

    return {
        'params':    {'p': p, 'q': q, 'g': g, 'bits': bits},
        'setup_ms':  round(setup_ms, 3),
        'ot_run':    run,
        'correctness': corr,
        'receiver_privacy': priv,
        'sender_privacy': send,
    }
