"""
PA #14 — Chinese Remainder Theorem & Breaking Textbook RSA
===========================================================
No-library rule: only Python builtins + PA#12/PA#13 utilities.

Exports (PA#17 interface)
--------------------------
crt(residues, moduli)          -> int
rsa_dec_crt(sk_crt, c)        -> int
hastad_attack(ciphertexts, moduli, e) -> int
"""

import time
from crypto.pa12_rsa import (
    mod_inverse, extended_gcd, gcd,
    rsa_keygen, rsa_enc, rsa_dec,
    pkcs15_enc, pkcs15_dec,
    _modulus_byte_len,
)
from crypto.pa13_miller_rabin import mod_exp


# ── 1. CRT Solver ─────────────────────────────────────────────────────────────

def crt(residues: list[int], moduli: list[int]) -> int:
    """
    Chinese Remainder Theorem solver.

    Given a list of congruences  x ≡ residues[i] (mod moduli[i])
    with pairwise coprime moduli, returns the unique x ∈ [0, N)
    where N = Π moduli[i].

    Uses the constructive formula:
        x = Σ  a_i * M_i * (M_i^-1 mod n_i)  (mod N)
    where M_i = N / n_i.

    All modular inverses are computed via the Extended Euclidean Algorithm
    (no math library).
    """
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")

    N = 1
    for m in moduli:
        N *= m

    x = 0
    for a_i, n_i in zip(residues, moduli):
        M_i   = N // n_i
        inv_i = mod_inverse(M_i, n_i)       # M_i^-1 mod n_i  (ext. Euclidean)
        x    += a_i * M_i * inv_i

    return x % N


# ── 2. CRT-Based RSA Decryption (Garner's Algorithm) ─────────────────────────

def rsa_dec_crt(sk_crt: dict, c: int) -> int:
    """
    Fast RSA decryption via Garner's recombination.

    sk_crt must contain: N, p, q, dp, dq, q_inv
      dp    = d mod (p-1)
      dq    = d mod (q-1)
      q_inv = q^-1 mod p

    Algorithm:
      mp = c^dp  mod p
      mq = c^dq  mod q
      h  = q_inv * (mp - mq)  mod p
      m  = mq + h * q

    Speedup: exponentiation uses ~half-size exponents (dp, dq) over
    half-size moduli (p, q), giving ≈4× speedup vs. standard decryption.
    """
    p, q   = sk_crt['p'],   sk_crt['q']
    dp, dq = sk_crt['dp'],  sk_crt['dq']
    q_inv  = sk_crt['q_inv']

    mp = mod_exp(c % p, dp, p)          # c^dp mod p
    mq = mod_exp(c % q, dq, q)          # c^dq mod q

    # Garner recombination
    h = (q_inv * (mp - mq)) % p
    m = mq + h * q
    return m


# ── 3. Integer e-th root via Newton's Method ──────────────────────────────────

def integer_eth_root(x: int, e: int) -> tuple[int, bool]:
    """
    Compute the integer e-th root of x using Newton's method.
    Returns (root, exact) where exact=True iff root^e == x.

    Works for arbitrarily large Python integers.
    """
    if x < 0:
        raise ValueError("Cannot take e-th root of a negative integer")
    if x == 0:
        return 0, True
    if e == 1:
        return x, True

    # Initial guess: 2^(ceil(x.bit_length() / e))
    bits = x.bit_length()
    r = 1 << ((bits + e - 1) // e)

    # Newton iteration: r_{k+1} = ((e-1)*r_k + x // r_k^(e-1)) // e
    while True:
        r_e1 = r ** (e - 1)
        r_new = ((e - 1) * r + x // r_e1) // e
        if r_new >= r:
            break
        r = r_new

    # Adjust ±1 for rounding
    while r ** e > x:
        r -= 1
    while (r + 1) ** e <= x:
        r += 1

    return r, (r ** e == x)


# ── 4. Hastad's Broadcast Attack ──────────────────────────────────────────────

def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> tuple[int, bool]:
    """
    Håstad's Broadcast Attack.

    Given e ciphertexts  c_i = m^e mod N_i  (same message m, same exponent e,
    different pairwise-coprime moduli N_i), recover m.

    Steps:
      1. Apply CRT to recover  x = m^e mod (N_0 * N_1 * ... * N_{e-1}).
         Since m < N_i for all i, we have m^e < Π N_i, so x = m^e exactly.
      2. Compute the integer e-th root of x.

    Returns (m, exact) where exact=True iff the integer root is perfect
    (i.e. the attack succeeded).
    """
    if len(ciphertexts) < e or len(moduli) < e:
        raise ValueError(f"Hastad's attack with e={e} requires at least {e} ciphertexts")

    # Use exactly e ciphertexts / moduli
    c_list = ciphertexts[:e]
    n_list = moduli[:e]

    x = crt(c_list, n_list)             # = m^e as an integer (no wrap-around)
    m, exact = integer_eth_root(x, e)
    return m, exact


# ── 5. Performance Benchmark ──────────────────────────────────────────────────

def benchmark_crt_vs_standard(bits: int = 1024, trials: int = 1000) -> dict:
    """
    Compare standard rsa_dec vs rsa_dec_crt over `trials` decryptions
    at the given key bit-size.

    Returns timings and speedup ratio (expected ≈ 3–4×).
    """
    import secrets as sec

    pk, sk, aux = rsa_keygen(bits)
    N = pk['N']

    sk_crt = {
        'N':     N,
        'p':     aux['p'],
        'q':     aux['q'],
        'dp':    aux['dp'],
        'dq':    aux['dq'],
        'q_inv': aux['q_inv'],
    }

    # Generate random plaintexts and encrypt them
    messages    = [sec.randbelow(N - 1) + 1 for _ in range(trials)]
    ciphertexts = [rsa_enc(pk, m)           for m in messages]

    # --- Standard decryption ---
    t0 = time.perf_counter()
    for c in ciphertexts:
        rsa_dec(sk, c)
    std_elapsed = time.perf_counter() - t0

    # --- CRT decryption ---
    t0 = time.perf_counter()
    for c in ciphertexts:
        rsa_dec_crt(sk_crt, c)
    crt_elapsed = time.perf_counter() - t0

    speedup = std_elapsed / crt_elapsed if crt_elapsed > 0 else float('inf')

    # Correctness check on a sample
    correct = all(
        rsa_dec_crt(sk_crt, c) == rsa_dec(sk, c)
        for c in ciphertexts[:10]
    )

    return {
        'bits':           bits,
        'trials':         trials,
        'std_total_ms':   round(std_elapsed * 1000, 3),
        'crt_total_ms':   round(crt_elapsed * 1000, 3),
        'std_per_dec_ms': round(std_elapsed / trials * 1000, 3),
        'crt_per_dec_ms': round(crt_elapsed / trials * 1000, 3),
        'speedup':        round(speedup, 2),
        'correctness_ok': correct,
    }


# ── 5b. Garner Correctness Verification (100 random messages) ─────────────────

def garner_correctness_check(bits: int = 512, n_messages: int = 100) -> dict:
    """
    Assignment requirement: verify rsa_dec_crt(sk, c) == rsa_dec(sk, c)
    for 100 random messages.

    Generates one RSA key pair, then for each of the n_messages random messages:
      - encrypts m  →  c
      - decrypts with standard:  m_std = c^d mod N
      - decrypts with Garner CRT: m_crt = Garner(c)
      - checks m_std == m_crt == m

    Returns per-row results and an overall pass/fail summary.
    """
    import secrets as sec

    t_total = time.perf_counter()

    pk, sk, aux = rsa_keygen(bits)
    N = pk['N']

    sk_crt = {
        'N':     N,
        'p':     aux['p'],
        'q':     aux['q'],
        'dp':    aux['dp'],
        'dq':    aux['dq'],
        'q_inv': aux['q_inv'],
    }

    rows = []
    all_match = True

    for i in range(n_messages):
        m = sec.randbelow(N - 1) + 1
        c = rsa_enc(pk, m)

        t0 = time.perf_counter()
        m_std = rsa_dec(sk, c)
        std_ms = round((time.perf_counter() - t0) * 1000, 4)

        t0 = time.perf_counter()
        m_crt = rsa_dec_crt(sk_crt, c)
        crt_ms = round((time.perf_counter() - t0) * 1000, 4)

        match = (m_std == m_crt == m)
        if not match:
            all_match = False

        rows.append({
            'row':     i + 1,
            'm':       str(m),
            'c':       str(c),
            'm_std':   str(m_std),
            'm_crt':   str(m_crt),
            'match':   match,
            'std_ms':  std_ms,
            'crt_ms':  crt_ms,
        })

    total_ms = round((time.perf_counter() - t_total) * 1000, 2)
    passed   = sum(1 for r in rows if r['match'])

    return {
        'bits':       bits,
        'n_messages': n_messages,
        'all_match':  all_match,
        'passed':     passed,
        'failed':     n_messages - passed,
        'total_ms':   total_ms,
        'N':          str(N),
        'rows':       rows,
    }


# ── 6. Attack-Boundary Analysis ───────────────────────────────────────────────

def hastad_boundary(n_bits: int = 64, e: int = 3) -> dict:
    """
    Determine the maximum message byte-length for which Hastad's
    broadcast attack succeeds.

    Hastad's attack works iff  m^e  <  N_1 * N_2 * ... * N_e.
    Each N_i is ~n_bits bits, so the bound is roughly:
        m  <  (N_1 * ... * N_e)^(1/e)  ≈  2^(n_bits)
    i.e. m must fit in ~n_bits bits.
    """
    # The product of e moduli each of n_bits bits has ~e*n_bits bits.
    # Safe message size: m^e < 2^(e * n_bits)  →  m < 2^(n_bits)
    max_bits  = n_bits             # m < 2^n_bits
    max_bytes = max_bits // 8

    return {
        'modulus_bits':  n_bits,
        'e':             e,
        'max_msg_bits':  max_bits,
        'max_msg_bytes': max_bytes,
        'explanation': (
            f"With e={e} moduli each ~{n_bits} bits, the CRT modulus is "
            f"~{e * n_bits} bits. Hastad's attack succeeds iff m^{e} < (CRT modulus), "
            f"i.e. m < 2^{n_bits} ≈ {max_bytes} bytes. "
            f"Longer messages 'wrap around' modulo N_i and the integer root step fails."
        ),
    }


# ── 7. Full Interactive Demo (toy 64-bit params) ─────────────────────────────

def hastad_demo(message: str, use_padding: bool = False, n_bits: int = 64) -> dict:
    """
    End-to-end Hastad Broadcast Attack demo for the frontend.

    Generates three independent RSA key pairs with e=3 and n_bits-bit moduli.
    The same message m is encrypted to all three recipients.
    The attacker collects the three ciphertexts and runs the CRT attack.

    If use_padding=True, each sender applies PKCS#1 v1.5 padding  before
    encrypting — the three padded values differ, so CRT recovers garbage
    and the cube-root step fails (exact=False).

    Returns a rich dict for the visualizer.
    """
    e = 3

    # -- Key generation (e=3, tiny moduli for instant computation) -----------
    t0 = time.perf_counter()
    keys = []
    for _ in range(e):
        pk_i, sk_i, aux_i = rsa_keygen(n_bits)
        # Force e=3 by regenerating if needed (gen_prime ensures MSB set)
        while True:
            from crypto.pa13_miller_rabin import gen_prime
            p, _, _ = gen_prime(n_bits // 2, k=20)
            q, _, _ = gen_prime(n_bits // 2, k=20)
            if p == q:
                continue
            N_i = p * q
            phi_i = (p - 1) * (q - 1)
            if gcd(e, phi_i) != 1:
                continue
            d_i   = mod_inverse(e, phi_i)
            dp_i  = d_i % (p - 1)
            dq_i  = d_i % (q - 1)
            qi_i  = mod_inverse(q, p)
            break
        pk_i  = {'N': N_i, 'e': e}
        sk_i  = {'N': N_i, 'd': d_i}
        aux_i = {'p': p, 'q': q, 'dp': dp_i, 'dq': dq_i, 'q_inv': qi_i}
        keys.append((pk_i, sk_i, aux_i))

    keygen_ms = (time.perf_counter() - t0) * 1000

    # -- Encode the message ---------------------------------------------------
    m_bytes = message.encode('utf-8')
    m_int   = int.from_bytes(m_bytes, 'big')

    # Validate: m < min(N_i)
    min_N = min(pk['N'] for pk, _, _ in keys)
    if m_int >= min_N:
        raise ValueError(
            f"Message integer {m_int} ≥ smallest modulus {min_N}. "
            f"Please use a shorter message (≤ {(min_N.bit_length() - 1) // 8} bytes)."
        )

    # -- Encrypt to each recipient -------------------------------------------
    recipients = []
    ciphertexts_attack = []
    moduli_attack      = []

    t_enc = time.perf_counter()
    for i, (pk_i, sk_i, aux_i) in enumerate(keys):
        N_i = pk_i['N']
        k_i = _modulus_byte_len(N_i)

        if use_padding:
            # For demo: use PKCS#1 v1.5 if modulus is large enough (k ≥ 11),
            # otherwise use a lightweight XOR-mask pad to show randomization.
            if k_i >= 11:
                padded_em = _pkcs_pad_for_hastad(m_bytes, k_i)
                m_enc_int = int.from_bytes(padded_em, 'big')
            else:
                # Tiny modulus: just XOR with a random mask byte to randomise
                import secrets as _sec
                mask = _sec.randbelow(256)
                raw = bytearray(k_i)
                raw[-len(m_bytes):] = m_bytes
                raw[0] = mask  # random leading byte — gives different int per recipient
                m_enc_int = int.from_bytes(raw, 'big') % N_i
        else:
            m_enc_int = m_int

        c_i = mod_exp(m_enc_int, e, N_i)

        recipients.append({
            'index':   i + 1,
            'N':       str(N_i),
            'N_hex':   hex(N_i),
            'e':       e,
            'c':       str(c_i),
            'c_hex':   hex(c_i),
            'padded':  use_padding,
        })
        ciphertexts_attack.append(c_i)
        moduli_attack.append(N_i)

    enc_ms = (time.perf_counter() - t_enc) * 1000

    # -- Attacker runs CRT + integer root ------------------------------------
    t_att = time.perf_counter()
    crt_product = 1
    for n in moduli_attack:
        crt_product *= n

    x = crt(ciphertexts_attack, moduli_attack)        # = m^3 (mod N1*N2*N3)
    recovered_int, exact = integer_eth_root(x, e)
    att_ms = (time.perf_counter() - t_att) * 1000

    # -- Decode result -------------------------------------------------------
    if exact:
        try:
            recovered_bytes = recovered_int.to_bytes(
                (recovered_int.bit_length() + 7) // 8, 'big'
            )
            recovered_str = recovered_bytes.decode('utf-8', errors='replace')
        except Exception:
            recovered_str = hex(recovered_int)
    else:
        # Integer root wasn't perfect — attack failed (expected with padding)
        recovered_bytes = recovered_int.to_bytes(
            max((recovered_int.bit_length() + 7) // 8, 1), 'big'
        )
        recovered_str = '[GARBAGE] ' + recovered_bytes.decode('utf-8', errors='replace')

    attack_succeeded = exact and (recovered_int == m_int)

    return {
        'message':           message,
        'message_hex':       m_bytes.hex(),
        'm_int':             str(m_int),
        'e':                 e,
        'use_padding':       use_padding,
        'recipients':        recipients,
        'crt_product':       str(crt_product),
        'crt_product_bits':  crt_product.bit_length(),
        'x_me':              str(x),              # recovered m^e
        'x_me_hex':          hex(x),
        'recovered_int':     str(recovered_int),
        'recovered_str':     recovered_str,
        'exact_root':        exact,
        'attack_succeeded':  attack_succeeded,
        'keygen_ms':         round(keygen_ms, 2),
        'enc_ms':            round(enc_ms, 2),
        'att_ms':            round(att_ms, 2),
        'n_bits':            n_bits,
    }


def _pkcs_pad_for_hastad(m_bytes: bytes, k: int) -> bytes:
    """Minimal PKCS#1 v1.5 type-2 pad for Hastad demo (uses secrets for random PS)."""
    import secrets
    m_len = len(m_bytes)
    if k < 11 or m_len > k - 11:
        raise ValueError(f"Message too long for {k}-byte modulus: needs k ≥ 11")
    ps_len = k - m_len - 3
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)
    return bytes([0x00, 0x02]) + bytes(ps) + bytes([0x00]) + m_bytes


# ── 8. Padding Defeats Attack Demo ───────────────────────────────────────────

def padding_breaks_hastad(message: str, n_bits: int = 64) -> dict:
    """
    Side-by-side: run hastad_demo twice (no padding, with padding).
    Returns both results for the 'why padding defeats the attack' section.
    """
    without = hastad_demo(message, use_padding=False, n_bits=n_bits)
    with_pad = hastad_demo(message, use_padding=True,  n_bits=n_bits)
    return {
        'without_padding': without,
        'with_padding':    with_pad,
    }
