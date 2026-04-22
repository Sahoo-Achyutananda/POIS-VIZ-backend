"""
PA #12 — Textbook RSA and PKCS#1 v1.5 Padding
===============================================
No-library rule: only Python builtins + PA#13 utilities.
Uses PA#13 gen_prime (Miller-Rabin) for prime generation.
Uses PA#13 mod_exp (square-and-multiply) for all exponentiation.
Implements own extended Euclidean algorithm (no math.gcd usage for inversion).

Exports (PA#14, PA#15, PA#18 interface)
----------------------------------------
rsa_keygen(bits)           -> pk, sk, aux
rsa_enc(pk, m_int)         -> c_int
rsa_dec(sk, c_int)         -> m_int
pkcs15_enc(pk, m_bytes)    -> c_int
pkcs15_dec(sk, c_int)      -> m_bytes
padding_oracle(sk, c_int)  -> bool
"""

import secrets
import time

from crypto.pa13_miller_rabin import gen_prime, mod_exp


# ── Extended Euclidean Algorithm ──────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Iterative extended Euclidean: returns (gcd, x, y) s.t. a*x + b*y = gcd.
    Iterative (not recursive) to handle very large exponents without stack overflow.
    """
    old_r, r   = a, b
    old_s, s   = 1, 0
    old_t, t   = 0, 1
    while r != 0:
        q       = old_r // r
        old_r, r   = r, old_r - q * r
        old_s, s   = s, old_s - q * s
        old_t, t   = t, old_t - q * t
    return old_r, old_s, old_t          # (gcd, coeff_a, coeff_b)


def mod_inverse(a: int, m: int) -> int:
    """Compute a^(-1) mod m. Raises ValueError if inverse doesn't exist."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"mod_inverse: gcd({a}, {m}) = {g} ≠ 1 — no inverse exists")
    return x % m


def gcd(a: int, b: int) -> int:
    """Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return a


# ── RSA Key Generation ─────────────────────────────────────────────────────────

def rsa_keygen(bits: int = 512) -> tuple[dict, dict, dict]:
    """
    Generate an RSA key pair of `bits`-bit modulus N = p*q.
    Each prime is bits//2 bits. Uses PA#13 gen_prime (Miller-Rabin, k=40).

    Returns:
        pk  = {'N': int, 'e': int}
        sk  = {'N': int, 'd': int}
        aux = {'p', 'q', 'dp', 'dq', 'q_inv', 'phi', 'bits', 'time_ms'}
            dp  = d mod (p-1)   ─┐ CRT components for
            dq  = d mod (q-1)   ─┤ fast decryption (PA#14)
            q_inv = q^-1 mod p  ─┘
    """
    half = max(bits // 2, 8)
    e = 65537

    t0 = time.perf_counter()
    while True:
        p, _, _ = gen_prime(half, k=40)
        q, _, _ = gen_prime(half, k=40)
        if q == p:
            continue
        # Ensure N has expected bit-length (both primes must have MSB set — gen_prime guarantees this)
        N = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) != 1:
            continue   # extremely rare; just resample
        break

    d     = mod_inverse(e, phi)
    dp    = d % (p - 1)
    dq    = d % (q - 1)
    q_inv = mod_inverse(q, p)
    elapsed = (time.perf_counter() - t0) * 1000

    # Sanity: e*d ≡ 1 (mod phi)
    assert (e * d) % phi == 1, "Key generation error: e*d ≢ 1 mod φ(N)"

    pk  = {'N': N, 'e': e}
    sk  = {'N': N, 'd': d}
    aux = {
        'p': p, 'q': q,
        'dp': dp, 'dq': dq, 'q_inv': q_inv,
        'phi': phi,
        'bits': N.bit_length(),
        'time_ms': round(elapsed, 3),
    }
    return pk, sk, aux


# ── Textbook RSA ───────────────────────────────────────────────────────────────

def rsa_enc(pk: dict, m: int) -> int:
    """
    Textbook RSA encryption: C = m^e mod N.
    m must be a non-negative integer < N.
    WARNING: deterministic — same plaintext always produces same ciphertext.
    """
    N, e = pk['N'], pk['e']
    if not (0 <= m < N):
        raise ValueError(f"Plaintext m={m} out of range [0, N-1]")
    return mod_exp(m, e, N)


def rsa_dec(sk: dict, c: int) -> int:
    """Textbook RSA decryption: M = c^d mod N."""
    N, d = sk['N'], sk['d']
    if not (0 <= c < N):
        raise ValueError(f"Ciphertext c={c} out of range [0, N-1]")
    return mod_exp(c, d, N)


# ── PKCS#1 v1.5 Padding ────────────────────────────────────────────────────────

def _modulus_byte_len(N: int) -> int:
    return (N.bit_length() + 7) // 8


def pkcs15_pad(m_bytes: bytes, k: int) -> bytes:
    """
    Apply PKCS#1 v1.5 type-2 encryption padding.
    Format: 0x00 | 0x02 | PS (≥ 8 random nonzero bytes) | 0x00 | m
    Total length = k (modulus byte length).
    """
    m_len = len(m_bytes)
    if m_len > k - 11:
        raise ValueError(
            f"Message too long for PKCS#1 v1.5: |m|={m_len} > k-11={k-11}"
        )
    ps_len = k - m_len - 3
    if ps_len < 8:
        raise ValueError(f"PS length {ps_len} < 8 (modulus too small)")

    # Generate ≥8 cryptographically random nonzero bytes for PS
    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.randbelow(256)
        if b != 0:
            ps.append(b)

    em = bytes([0x00, 0x02]) + bytes(ps) + bytes([0x00]) + m_bytes
    assert len(em) == k, f"Padded length {len(em)} != k={k}"
    return em


def pkcs15_unpad(em: bytes, k: int) -> bytes:
    """
    Strip and validate PKCS#1 v1.5 type-2 padding.
    Returns message bytes on success; raises ValueError on any malformed input.
    """
    if len(em) != k:
        raise ValueError(f"EM length {len(em)} ≠ k={k}")
    if em[0] != 0x00:
        raise ValueError("Invalid PKCS#1 v1.5: EM[0] ≠ 0x00")
    if em[1] != 0x02:
        raise ValueError(f"Invalid PKCS#1 v1.5: EM[1] = 0x{em[1]:02x} ≠ 0x02")

    # Find 0x00 separator (must be at index ≥ 10, i.e., PS ≥ 8 bytes)
    try:
        sep = em.index(0x00, 2)
    except ValueError:
        raise ValueError("Invalid PKCS#1 v1.5: no 0x00 separator found")

    ps_len = sep - 2
    if ps_len < 8:
        raise ValueError(f"Invalid PKCS#1 v1.5: PS length {ps_len} < 8")

    return em[sep + 1:]


def pkcs15_enc(pk: dict, m_bytes: bytes) -> int:
    """
    PKCS#1 v1.5 encrypt: pad m_bytes then apply textbook RSA.
    Returns ciphertext integer.
    """
    k = _modulus_byte_len(pk['N'])
    em = pkcs15_pad(m_bytes, k)
    m_int = int.from_bytes(em, 'big')
    return rsa_enc(pk, m_int)


def pkcs15_dec(sk: dict, c: int) -> bytes:
    """
    PKCS#1 v1.5 decrypt: textbook RSA decrypt then strip and validate padding.
    Returns plaintext bytes; raises ValueError on invalid padding (padding oracle boundary).
    """
    N = sk['N']
    k = _modulus_byte_len(N)
    m_int = rsa_dec(sk, c)
    # Left-pad with 0x00 bytes to full k bytes
    try:
        em = m_int.to_bytes(k, 'big')
    except OverflowError:
        raise ValueError("Decrypted value overflows modulus byte length")
    return pkcs15_unpad(em, k)


# ── Padding Oracle ─────────────────────────────────────────────────────────────

def padding_oracle(sk: dict, c: int) -> bool:
    """
    Returns True iff c decrypts to a valid PKCS#1 v1.5 type-2 padded message.
    In a real attack this would be a remote service; here it's the known secret key.
    """
    try:
        pkcs15_dec(sk, c)
        return True
    except (ValueError, OverflowError):
        return False


# ── Determinism Attack Demo ───────────────────────────────────────────────────

def determinism_demo(pk: dict, sk: dict, message: str) -> dict:
    """
    Demonstrate that textbook RSA is deterministic (same plaintext → same ciphertext)
    while PKCS#1 v1.5 randomises via PS (different PS → different ciphertext each time).

    Returns a rich dict with both ciphertexts, hex representations, and PS bytes.
    """
    m_bytes = message.encode('utf-8')
    m_int   = int.from_bytes(m_bytes, 'big')
    N       = pk['N']
    k       = _modulus_byte_len(N)

    if m_int >= N:
        raise ValueError(f"Message integer {m_int} ≥ N — use a shorter message")

    # Textbook: two encryptions, guaranteed identical
    tb_c1 = rsa_enc(pk, m_int)
    tb_c2 = rsa_enc(pk, m_int)

    # PKCS#1 v1.5: two encryptions, different PS each time
    # Also capture the padded EM so we can extract PS bytes for display
    em1 = pkcs15_pad(m_bytes, k)
    em2 = pkcs15_pad(m_bytes, k)
    pkcs_c1 = rsa_enc(pk, int.from_bytes(em1, 'big'))
    pkcs_c2 = rsa_enc(pk, int.from_bytes(em2, 'big'))

    # Extract PS bytes (em[2 .. sep-1])
    sep1 = em1.index(0x00, 2)
    sep2 = em2.index(0x00, 2)
    ps1  = em1[2:sep1]
    ps2  = em2[2:sep2]

    # Verify textbook decryption round-trips
    assert rsa_dec(sk, tb_c1) == m_int

    return {
        'message': message,
        'message_hex': m_bytes.hex(),
        'textbook': {
            'c1': tb_c1,
            'c2': tb_c2,
            'c1_hex': hex(tb_c1),
            'c2_hex': hex(tb_c2),
            'identical': tb_c1 == tb_c2,        # ALWAYS True
        },
        'pkcs15': {
            'c1': pkcs_c1,
            'c2': pkcs_c2,
            'c1_hex': hex(pkcs_c1),
            'c2_hex': hex(pkcs_c2),
            'identical': pkcs_c1 == pkcs_c2,    # ALWAYS False
            'ps1_hex': ps1.hex(),
            'ps2_hex': ps2.hex(),
            'ps1_len': len(ps1),
            'ps2_len': len(ps2),
        },
    }


# ── Simplified Bleichenbacher Padding Oracle Demo ────────────────────────────

def bleichenbacher_demo(pk: dict, sk: dict, message: str) -> dict:
    """
    Simplified Bleichenbacher CCA2 demo.

    The full 1998 attack recovers any plaintext with ≈2^20 oracle queries.
    This demo shows the KEY IDEAS:
      1. RSA multiplicative property: enc(m*s mod N) = enc(m) * enc(s) mod N
      2. Padding oracle leaks whether multiplied ciphertext is a valid PKCS message
      3. By scanning s values, attacker learns 'm*s mod N is in [2B, 3B-1]'
         for each valid oracle response, progressively narrowing bounds on m.

    For the toy 512-bit demo, we show:
      - The original ciphertext IS valid (oracle returns True)
      - Several multiplied variants, some valid, some not
      - How the 'valid' responses constrain the plaintext range
    """
    m_bytes = message.encode('utf-8')
    N, e    = pk['N'], pk['e']
    k       = _modulus_byte_len(N)

    if len(m_bytes) > k - 11:
        raise ValueError(f"Message too long for {k}-byte modulus (PKCS needs k-11≥|m|)")

    # Encrypt the target message (adversary has this ciphertext)
    c = pkcs15_enc(pk, m_bytes)

    # B = 2^(8*(k-2)) — lower bound for a valid PKCS#1 v1.5 EM integer
    B = 2 ** (8 * (k - 2))
    B_hex = hex(B)

    # --- Show oracle queries ---
    oracle_queries = []
    t0 = time.perf_counter()

    # Original ciphertext: should be valid
    valid_orig = padding_oracle(sk, c)
    oracle_queries.append({'s': 1, 'valid': valid_orig,
                           'note': 'Original c (s=1): multiplying by 1^e = 1 gives c itself'})

    # Scan small multipliers to build intuition
    valid_count = 0
    for s in range(2, 200):
        # Adversary computes c' = c * s^e mod N → decrypts to m*s mod N
        c_prime = (c * mod_exp(s, e, N)) % N
        valid = padding_oracle(sk, c_prime)
        if valid or s <= 10:   # always show first 10, then only valid ones
            oracle_queries.append({
                's': s,
                'valid': valid,
                'note': f'c * {s}^e mod N → plaintext m*{s} mod N',
            })
        if valid:
            valid_count += 1
            if valid_count >= 3:    # show first 3 valid hits then stop
                break

    elapsed = (time.perf_counter() - t0) * 1000

    # Verify we can recover the message (attacker has sk here for demo purposes)
    recovered = pkcs15_dec(sk, c).decode('utf-8', errors='replace')

    # Show that c * N^e = c (multiplying by 0 mod N is degenerate)
    return {
        'message': message,
        'c': c,
        'c_hex': hex(c),
        'B': B,
        'B_hex': B_hex,
        'k': k,
        'oracle_queries': oracle_queries[:20],     # cap at 20 for display
        'valid_oracle_hits': valid_count,
        'total_queries': len(oracle_queries),
        'elapsed_ms': round(elapsed, 3),
        'recovered_message': recovered,
        'key_insight': (
            f'For a valid PKCS#1 v1.5 message, EM ∈ [2B, 3B-1] where B = 2^(8*{k-2}). '
            f'Each oracle response shrinks the set of possible s values that satisfy this. '
            f'Full Bleichenbacher requires ~2^20 adaptive queries to fully recover m.'
        ),
    }


# ── Encrypt/Decrypt helpers (PA#14, PA#15, PA#18 interface) ───────────────────

def enc(pk: dict, m_bytes: bytes, mode: str = 'pkcs15') -> int:
    """Unified encrypt: mode='textbook' or 'pkcs15'."""
    if mode == 'textbook':
        m_int = int.from_bytes(m_bytes, 'big')
        return rsa_enc(pk, m_int)
    elif mode == 'pkcs15':
        return pkcs15_enc(pk, m_bytes)
    else:
        raise ValueError(f"Unknown mode: {mode!r}")


def dec(sk: dict, c: int, mode: str = 'pkcs15') -> bytes:
    """Unified decrypt: mode='textbook' or 'pkcs15'."""
    if mode == 'textbook':
        m_int = rsa_dec(sk, c)
        k = _modulus_byte_len(sk['N'])
        return m_int.to_bytes(k, 'big').lstrip(b'\x00')
    elif mode == 'pkcs15':
        return pkcs15_dec(sk, c)
    else:
        raise ValueError(f"Unknown mode: {mode!r}")
