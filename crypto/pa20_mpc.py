"""
PA #20 — 2-Party Secure Computation via Boolean Circuit Evaluation
===================================================================
No-library rule: builds on PA#19 gates → PA#18 OT → PA#16 ElGamal → PA#11 DH → PA#13 mod_exp.

Circuits implemented using AND / XOR / NOT gates from PA#19:

1. Millionaire's Problem — x > y for n-bit integers (x, y ∈ {0,...,2^n-1})
   Uses a bitwise comparator circuit built from AND, XOR, NOT gates.

2. Secure Equality — x == y for n-bit integers
   x == y  ⟺  (x XOR y) has no bit set  ⟺  NOT(OR of all bits of x⊕y)
   OR(a,b) = NOT(NOT(a) AND NOT(b))  →  decomposed into AND/XOR/NOT.

3. Secure Bit-Addition — 1-bit full adder (sum, carry) for PA#20
   sum   = a XOR b XOR cin
   carry = (a AND b) XOR (b AND cin) XOR (a AND cin)

All gate evaluations are done by calling secure_and / secure_xor / secure_not from PA#19.
Each real AND call invokes a full OT round (PA#18).

Lineage: PA#20 → PA#19 → PA#18 → PA#16 → PA#11 → PA#13
"""

import time
from crypto.pa19_secure_gates import secure_and, secure_xor, secure_not
from crypto.pa11_dh import gen_dh_params


# ── Gate helpers (wire up to secure gates with trace collection) ──────────────

class GateEvaluator:
    """
    Wraps PA#19 gates and collects a trace of every gate evaluation.
    All gate calls are "secure" — AND uses OT, XOR/NOT are free.
    """
    def __init__(self, p, q, g):
        self.p = p; self.q = q; self.g = g
        self.trace  = []     # list of gate evaluation records
        self.ot_calls = 0

    def AND(self, a, b, label='AND'):
        r = secure_and(self.p, self.q, self.g, a, b)
        self.ot_calls += 1
        self.trace.append({
            'gate': 'AND', 'label': label,
            'inputs': [a, b], 'output': r['result'],
            'ot': True, 'ms': r['total_ms'],
        })
        return r['result']

    def XOR(self, a, b, label='XOR'):
        r = secure_xor(a, b)
        self.trace.append({
            'gate': 'XOR', 'label': label,
            'inputs': [a, b], 'output': r['result'],
            'ot': False, 'ms': 0,
        })
        return r['result']

    def NOT(self, a, label='NOT'):
        r = secure_not(a)
        self.trace.append({
            'gate': 'NOT', 'label': label,
            'inputs': [a], 'output': r['result'],
            'ot': False, 'ms': 0,
        })
        return r['result']

    def OR(self, a, b, label='OR'):
        # OR(a,b) = NOT(NOT(a) AND NOT(b))
        na  = self.NOT(a, f'NOT_a({label})')
        nb  = self.NOT(b, f'NOT_b({label})')
        res = self.NOT(self.AND(na, nb, f'AND_nn({label})'), f'NOT_result({label})')
        return res


# ── Circuit 1: Millionaire's Problem — x > y (n-bit) ─────────────────────────

def _bits(x: int, n: int):
    """Return MSB-first bit list of x padded to n bits."""
    return [(x >> (n - 1 - i)) & 1 for i in range(n)]


def millionaires(p: int, q: int, g: int, x: int, y: int, n_bits: int = 4) -> dict:
    """
    Secure greater-than: both parties learn (x > y) ∈ {0,1}.
    Alice holds x, Bob holds y.

    Algorithm (1-bit comparator chain, MSB first):
      gt_prev = 0, eq_prev = 1
      For each bit position i (MSB → LSB):
        xi = bit i of x,  yi = bit i of y
        gt_i = xi AND NOT(yi)           -- this bit: x > y locally
        eq_i = NOT(xi XOR yi)           -- this bit: x == y
        gt_new = gt_prev OR (eq_prev AND gt_i)
        eq_new = eq_prev AND eq_i
    """
    if x < 0 or y < 0 or x >= 2**n_bits or y >= 2**n_bits:
        raise ValueError(f"x,y must be in [0, {2**n_bits - 1}]")

    t0 = time.perf_counter()
    ev = GateEvaluator(p, q, g)
    xb = _bits(x, n_bits)
    yb = _bits(y, n_bits)

    gt = 0   # x > y so far
    eq = 1   # x == y so far

    for i in range(n_bits):
        xi, yi = xb[i], yb[i]
        not_yi = ev.NOT(yi,       f'NOT_yi[{i}]')
        gt_i   = ev.AND(xi, not_yi, f'GT_bit[{i}]')
        xor_i  = ev.XOR(xi, yi,    f'XOR_bit[{i}]')
        eq_i   = ev.NOT(xor_i,     f'EQ_bit[{i}]')

        eq_gt_i  = ev.AND(eq,   gt_i,  f'EQ_AND_GT[{i}]')
        new_gt   = ev.OR( gt,   eq_gt_i, f'GT_update[{i}]')
        new_eq   = ev.AND(eq,   eq_i,   f'EQ_update[{i}]')
        gt, eq   = new_gt, new_eq

    expected = int(x > y)
    elapsed  = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "circuit":   "Millionaire's Problem (x > y)",
        "x": x, "y": y, "n_bits": n_bits,
        "result":    gt,
        "expected":  expected,
        "correct":   gt == expected,
        "ot_calls":  ev.ot_calls,
        "gate_trace": ev.trace,
        "elapsed_ms": elapsed,
        "privacy": {
            "alice_learns": f"x > y = {gt}",
            "bob_learns":   f"x > y = {gt}",
            "alice_hidden": "y (Bob's input never revealed in plaintext)",
            "bob_hidden":   "x (Alice's input never revealed in plaintext)",
        },
    }


# ── Circuit 2: Secure Equality — x == y (n-bit) ──────────────────────────────

def secure_equality(p: int, q: int, g: int, x: int, y: int, n_bits: int = 4) -> dict:
    """
    Secure equality: both learn (x == y) ∈ {0,1}.
    x == y  ⟺  XOR of all bits is 0 for every position.
    eq = AND of all NOT(xi XOR yi) over all i.
    """
    if x < 0 or y < 0 or x >= 2**n_bits or y >= 2**n_bits:
        raise ValueError(f"x,y must be in [0, {2**n_bits - 1}]")

    t0 = time.perf_counter()
    ev = GateEvaluator(p, q, g)
    xb = _bits(x, n_bits)
    yb = _bits(y, n_bits)

    eq = 1
    for i in range(n_bits):
        xor_i = ev.XOR(xb[i], yb[i], f'XOR[{i}]')
        neq_i = ev.NOT(xor_i,        f'NOT_XOR[{i}]')   # 1 if bits equal
        eq    = ev.AND(eq, neq_i,    f'EQ_acc[{i}]')

    expected = int(x == y)
    elapsed  = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "circuit":   "Secure Equality (x == y)",
        "x": x, "y": y, "n_bits": n_bits,
        "result":    eq,
        "expected":  expected,
        "correct":   eq == expected,
        "ot_calls":  ev.ot_calls,
        "gate_trace": ev.trace,
        "elapsed_ms": elapsed,
        "privacy": {
            "alice_learns": f"x == y = {eq}",
            "bob_learns":   f"x == y = {eq}",
            "alice_hidden": "y",
            "bob_hidden":   "x",
        },
    }


# ── Circuit 3: Secure 1-bit Full Adder ───────────────────────────────────────

def secure_full_adder(p: int, q: int, g: int,
                      a: int, b: int, cin: int = 0) -> dict:
    """
    Secure 1-bit full adder: computes (sum, carry) from (a, b, cin).
    sum   = a XOR b XOR cin
    carry = (a AND b) OR (b AND cin) OR (a AND cin)
    """
    t0 = time.perf_counter()
    ev = GateEvaluator(p, q, g)

    axb  = ev.XOR(a, b,   'XOR_a_b')
    s    = ev.XOR(axb, cin, 'SUM')

    ab   = ev.AND(a,   b,   'AND_a_b')
    bc   = ev.AND(b,   cin, 'AND_b_cin')
    ac   = ev.AND(a,   cin, 'AND_a_cin')
    c1   = ev.OR( ab,  bc,  'OR_ab_bc')
    co   = ev.OR( c1,  ac,  'CARRY')

    expected_s  = (a ^ b ^ cin) & 1
    expected_co = ((a & b) | (b & cin) | (a & cin)) & 1
    elapsed     = round((time.perf_counter() - t0) * 1000, 2)

    return {
        "circuit":   "1-bit Full Adder",
        "a": a, "b": b, "cin": cin,
        "sum":         s,
        "carry":       co,
        "expected_sum": expected_s,
        "expected_carry": expected_co,
        "correct":    (s == expected_s and co == expected_co),
        "ot_calls":   ev.ot_calls,
        "gate_trace": ev.trace,
        "elapsed_ms": elapsed,
        "privacy": {
            "alice_learns": f"sum={s}, carry={co}",
            "bob_learns":   f"sum={s}, carry={co}",
            "alice_hidden": "b, cin",
            "bob_hidden":   "a, cin",
        },
    }


# ── Correctness sweep ─────────────────────────────────────────────────────────

def correctness_sweep(p: int, q: int, g: int, n_bits: int = 2) -> dict:
    """
    Run Millionaire's, Equality, and Full-Adder over all (x,y) combos
    for n_bits-bit inputs. Confirm 100% correctness.
    """
    t0 = time.perf_counter()
    MAX = 2 ** n_bits
    results = {'millionaires': [], 'equality': [], 'adder': []}

    for x in range(MAX):
        for y in range(MAX):
            m = millionaires(p, q, g, x, y, n_bits)
            results['millionaires'].append({
                'x': x, 'y': y,
                'result': m['result'], 'expected': m['expected'],
                'correct': m['correct'],
            })
            e = secure_equality(p, q, g, x, y, n_bits)
            results['equality'].append({
                'x': x, 'y': y,
                'result': e['result'], 'expected': e['expected'],
                'correct': e['correct'],
            })

    # Adder: all (a, b, cin) combos
    for a in [0, 1]:
        for b in [0, 1]:
            for cin in [0, 1]:
                fa = secure_full_adder(p, q, g, a, b, cin)
                results['adder'].append({
                    'a': a, 'b': b, 'cin': cin,
                    'sum': fa['sum'], 'carry': fa['carry'],
                    'correct': fa['correct'],
                })

    m_pass = all(r['correct'] for r in results['millionaires'])
    e_pass = all(r['correct'] for r in results['equality'])
    a_pass = all(r['correct'] for r in results['adder'])

    return {
        "all_pass":       m_pass and e_pass and a_pass,
        "millionaires":   {"pass": m_pass, "results": results['millionaires']},
        "equality":       {"pass": e_pass, "results": results['equality']},
        "adder":          {"pass": a_pass, "results": results['adder']},
        "elapsed_ms":     round((time.perf_counter() - t0) * 1000, 2),
    }


# ── Full demo ─────────────────────────────────────────────────────────────────

def full_demo(bits: int = 32, x: int = 5, y: int = 3) -> dict:
    t0 = time.perf_counter()
    params   = gen_dh_params(bits)
    p, q, g  = params['p'], params['q'], params['g']
    setup_ms = round((time.perf_counter() - t0) * 1000, 2)

    # Clamp x, y to 4-bit range
    x = x % 16; y = y % 16

    r_mill  = millionaires(p, q, g, x, y, n_bits=4)
    r_eq    = secure_equality(p, q, g, x, y, n_bits=4)
    r_adder = secure_full_adder(p, q, g, x & 1, y & 1, cin=0)

    return {
        "params":      {"p": p, "q": q, "g": g, "bits": bits},
        "setup_ms":    setup_ms,
        "millionaires": r_mill,
        "equality":    r_eq,
        "adder":       r_adder,
    }
