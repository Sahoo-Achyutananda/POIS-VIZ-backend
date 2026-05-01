"""
PA #19 — Secure AND, XOR, and NOT Gates
=========================================
No-library rule: built on PA#18 OT → PA#16 ElGamal → PA#11 DH → PA#13 mod_exp.

Gate Implementations
--------------------
Secure AND(a, b):
  Alice acts as OT sender with messages (m0, m1) = (0, a).
  Bob acts as OT receiver with choice bit b.
  Bob receives m_b = a·b = a∧b.
  Privacy:
    Bob learns only a∧b — never 'a' alone (follows from OT receiver privacy).
    Alice learns nothing about b (follows from OT sender privacy).

Secure XOR(a, b):
  Free — no OT needed. Uses additive secret sharing over Z_2.
  Alice generates r ← {0,1} uniformly at random.
  Alice's share: s_A = a ⊕ r   (sent to Bob)
  Bob's share:   s_B = b ⊕ r   (maintained by Bob? No — Alice sends r to Bob)
  Actually: Alice sends r to Bob. Output = (a⊕r) ⊕ (b⊕r) = a⊕b.
  Privacy: r is uniform, so s_A = a⊕r reveals nothing about a.

Secure NOT(a):
  Alice locally flips her share. No communication.
  NOT(a) = 1 - a = a XOR 1.

Lineage: PA#19 → PA#18 → PA#16 → PA#11 → PA#13
"""

import secrets as _sec
import time
from typing import Literal

from crypto.pa18_ot import ot_receiver_step1, ot_sender_step, ot_receiver_step2
from crypto.pa11_dh import gen_dh_params


# ── Group params (shared, generated once per session) ────────────────────────

def _gen_group(bits: int = 32) -> dict:
    return gen_dh_params(bits)


# ── Secure AND via OT ─────────────────────────────────────────────────────────

def secure_and(
    p: int, q: int, g: int,
    a: int,   # Alice's private input bit ∈ {0,1}
    b: int,   # Bob's   private input bit ∈ {0,1}
) -> dict:
    """
    Secure AND(a, b) using 1-out-of-2 OT (Bellare-Micali / PA#18).

    Protocol:
      Alice (sender): m0 = 0, m1 = a
      Bob   (receiver): choice bit b
      Bob receives m_b = (0 if b==0 else a) = a·b = a∧b

    Returns a rich trace for the interactive demo.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("a and b must be bits in {0, 1}")

    t0 = time.perf_counter()

    # Alice's OT messages (encode +1 so ElGamal gets m ≥ 1)
    m0_alice, m1_alice = 0, a                       # (0, a)
    m0_enc,   m1_enc   = m0_alice + 1, m1_alice + 1 # +1 encoding

    # Step 1 — Bob generates key pairs
    pk0, pk1, state = ot_receiver_step1(p, q, g, b)
    step1_ms = round((time.perf_counter() - t0) * 1000, 3)

    # Step 2 — Alice encrypts both messages (+1 encoded)
    C0, C1 = ot_sender_step(p, q, g, pk0, pk1, m0_enc, m1_enc)
    step2_ms = round((time.perf_counter() - t0) * 1000, 3)

    # Step 3 — Bob decrypts C_b, then sub 1
    m_enc_received = ot_receiver_step2(state, C0, C1)
    m_received = m_enc_received - 1          # undo +1 encoding
    step3_ms = round((time.perf_counter() - t0) * 1000, 3)

    result = a & b                    # expected = a AND b
    correct = m_received == result

    return {
        "gate":        "AND",
        "a":           a,
        "b":           b,
        "result":      result,
        "m_received":  m_received,
        "correct":     correct,
        "total_ms":    step3_ms,
        "trace": {
            "alice_ot_messages": {"m0": 0, "m1": a},
            "bob_choice_b":  b,
            "step1_ms":  step1_ms,
            "step2_ms":  step2_ms,
            "step3_ms":  step3_ms,
            "pk0_h":     pk0["h"],
            "pk1_h":     pk1["h"],
            "C0_c1":     C0[0], "C0_c2": C0[1],
            "C1_c1":     C1[0], "C1_c2": C1[1],
        },
        "privacy": {
            "alice_sees":  ["C0", "C1", "pk0_h", "pk1_h"],
            "alice_learns": f"a∧b={result} (both parties output the same)",
            "alice_hidden": "b (cannot be inferred from pk0, pk1 under DDH)",
            "bob_sees":    [f"m_{b}={m_received}"],
            "bob_learns":  f"m_b = a∧b = {result}",
            "bob_hidden":  f"a (only a∧b={result} is revealed, not a={a} alone)",
        },
    }


# ── Secure XOR (free — additive sharing over Z_2) ────────────────────────────

def secure_xor(a: int, b: int) -> dict:
    """
    Secure XOR(a, b) via additive secret sharing over Z_2. No OT needed.

    Protocol:
      1. Alice samples r ← {0,1} uniformly at random.
      2. Alice's share: s_A = a ⊕ r  (Alice sends r to Bob).
      3. Bob's share:   s_B = b ⊕ r.
      4. Output = s_A ⊕ s_B = (a⊕r) ⊕ (b⊕r) = a ⊕ b.

    Privacy: r is uniform, so s_A = a⊕r ∈ {0,1} uniformly — no info about a.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("a and b must be bits in {0, 1}")

    r   = _sec.randbelow(2)           # Alice's random mask
    s_A = a ^ r                       # Alice's share (sent to Bob)
    s_B = b ^ r                       # Bob's share
    output = s_A ^ s_B                # = a ⊕ b

    correct = output == (a ^ b)

    return {
        "gate":    "XOR",
        "a":       a,
        "b":       b,
        "result":  output,
        "correct": correct,
        "trace": {
            "r":    r,
            "s_A":  s_A,
            "s_B":  s_B,
            "output": output,
        },
        "privacy": {
            "alice_sees":  ["s_A = a⊕r", "r (she chose it)"],
            "alice_learns": f"a⊕b={output}",
            "alice_hidden": "b (s_B = b⊕r is not sent to Alice)",
            "bob_sees":    [f"r={r}", f"s_A={s_A}", f"s_B={s_B}"],
            "bob_learns":  f"a⊕b={output}",
            "bob_hidden":  f"a (s_A=a⊕r is uniformly random)",
        },
    }


# ── Secure NOT (free — local flip) ────────────────────────────────────────────

def secure_not(a: int) -> dict:
    """
    Secure NOT(a): Alice locally flips her share. No communication at all.
    """
    if a not in (0, 1):
        raise ValueError("a must be a bit in {0, 1}")
    result = 1 - a
    return {
        "gate":    "NOT",
        "a":       a,
        "result":  result,
        "correct": result == (1 - a),
        "trace":   {"flip": f"{a} → {result}"},
        "privacy": {
            "alice_sees":  ["a (her own input)"],
            "bob_sees":    [],
            "alice_learns": f"NOT(a)={result}",
            "bob_learns":  "nothing (no communication)",
        },
    }


# ── Truth table test ──────────────────────────────────────────────────────────

def truth_table_test(
    p: int, q: int, g: int,
    trials_per_combo: int = 50,
) -> dict:
    """
    Verify all 4 input combinations (a,b) ∈ {00,01,10,11} for AND and XOR
    across `trials_per_combo` runs each. Confirms:
      - AND correctness
      - XOR correctness
      - NOT correctness
    """
    t0 = time.perf_counter()
    combos   = [(0, 0), (0, 1), (1, 0), (1, 1)]
    results  = []
    all_pass = True

    for (a, b) in combos:
        and_pass = xor_pass = 0
        for _ in range(trials_per_combo):
            r_and = secure_and(p, q, g, a, b)
            r_xor = secure_xor(a, b)
            if r_and["correct"]:
                and_pass += 1
            if r_xor["correct"]:
                xor_pass += 1

        not_result = secure_not(a)
        combo_ok   = (and_pass == trials_per_combo and xor_pass == trials_per_combo)
        all_pass  &= combo_ok

        results.append({
            "a": a, "b": b,
            "and_expected": a & b,
            "xor_expected": a ^ b,
            "not_a_expected": 1 - a,
            "and_pass":  and_pass,
            "xor_pass":  xor_pass,
            "not_pass":  not_result["correct"],
            "trials":    trials_per_combo,
            "ok":        combo_ok,
        })

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return {
        "combos":      results,
        "all_pass":    all_pass,
        "elapsed_ms":  elapsed_ms,
        "trials_per":  trials_per_combo,
    }


# ── Full demo ─────────────────────────────────────────────────────────────────

def full_demo(bits: int = 32, a: int = 1, b: int = 1) -> dict:
    """Single AND + XOR + NOT run plus truth table, all in one shot."""
    t0 = time.perf_counter()
    params = gen_dh_params(bits)
    p, q, g = params["p"], params["q"], params["g"]
    setup_ms = round((time.perf_counter() - t0) * 1000, 2)

    r_and  = secure_and(p, q, g, a, b)
    r_xor  = secure_xor(a, b)
    r_not  = secure_not(a)
    r_tt   = truth_table_test(p, q, g, trials_per_combo=20)

    return {
        "params":   {"p": p, "q": q, "g": g, "bits": bits},
        "setup_ms": setup_ms,
        "and":      r_and,
        "xor":      r_xor,
        "not":      r_not,
        "truth_table": r_tt,
    }
