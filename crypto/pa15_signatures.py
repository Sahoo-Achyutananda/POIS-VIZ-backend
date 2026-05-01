"""
PA #15 — Digital Signatures
============================
No-library rule: only Python builtins + PA#12/PA#13 utilities + PureSHA256.

Sign  : σ = H(m)^d  mod N          (hash-then-sign)
Verify: σ^e mod N  ==  H(m)        (verify)

Existential Forgery (raw RSA, no hash):
  Given σ₁ = m₁^d mod N and σ₂ = m₂^d mod N,
  forge σ = (σ₁ · σ₂) mod N for m = m₁·m₂ mod N — no private key needed.

Exports (PA#17 interface)
--------------------------
sign(sk, m_bytes|str)          -> int  (sigma)
verify(vk, m_bytes|str, sigma) -> bool
"""

import time
import secrets as _sec

from crypto.sha256_pure import PureSHA256
from crypto.pa12_rsa import (
    rsa_keygen, rsa_enc, rsa_dec,
    mod_inverse, extended_gcd, gcd,
    _modulus_byte_len,
)
from crypto.pa13_miller_rabin import mod_exp


# ── Hash helper ────────────────────────────────────────────────────────────────

def _sha256_int(data: bytes) -> int:
    """SHA-256(data) as a Python integer (256-bit)."""
    h = PureSHA256(data)
    return int.from_bytes(h.digest(), 'big')


def _to_bytes(m) -> bytes:
    """Accept str or bytes, return bytes."""
    if isinstance(m, str):
        return m.encode('utf-8')
    return bytes(m)


# ── 1. RSA Hash-then-Sign ──────────────────────────────────────────────────────

def sign(sk: dict, m) -> int:
    """
    RSA hash-then-sign: σ = SHA256(m)^d mod N.

    The hash is reduced modulo N so it fits in [0, N).
    sk must contain 'N' and 'd'.
    """
    m_bytes = _to_bytes(m)
    N, d    = sk['N'], sk['d']
    h       = _sha256_int(m_bytes) % N
    return mod_exp(h, d, N)


def verify(vk: dict, m, sigma: int) -> bool:
    """
    RSA signature verification: check σ^e mod N == SHA256(m) mod N.
    vk must contain 'N' and 'e'.
    """
    m_bytes = _to_bytes(m)
    N, e    = vk['N'], vk['e']
    h       = _sha256_int(m_bytes) % N
    return mod_exp(sigma, e, N) == h


# ── 2. Raw RSA Sign (no hash) — for forgery demo ──────────────────────────────

def sign_raw(sk: dict, m_bytes: bytes) -> int:
    """
    Textbook raw RSA signature: σ = m^d mod N (NO hashing).
    INSECURE — only for demonstrating the multiplicative forgery.
    """
    N, d = sk['N'], sk['d']
    m_int = int.from_bytes(m_bytes, 'big') % N
    return mod_exp(m_int, d, N)


def verify_raw(vk: dict, m_bytes: bytes, sigma: int) -> bool:
    """Verify raw RSA signature: σ^e mod N == m_int."""
    N, e    = vk['N'], vk['e']
    m_int   = int.from_bytes(m_bytes, 'big') % N
    return mod_exp(sigma, e, N) == m_int


# ── 3. Multiplicative Forgery Attack ──────────────────────────────────────────

def multiplicative_forgery(vk: dict, m1_bytes: bytes, sig1: int,
                           m2_bytes: bytes, sig2: int) -> dict:
    """
    Existential forgery without the private key.

    Given valid raw-RSA signatures:
      σ₁ = m₁^d mod N  and  σ₂ = m₂^d mod N

    Compute a valid signature on  m_forged = m₁·m₂ mod N:
      σ_forged = (σ₁ · σ₂) mod N = (m₁·m₂)^d mod N

    This exploits the multiplicative homomorphism of raw RSA.
    Returns the forged message, forged signature, and verification result.
    """
    N, e = vk['N'], vk['e']

    m1_int = int.from_bytes(m1_bytes, 'big') % N
    m2_int = int.from_bytes(m2_bytes, 'big') % N

    # Forge — attacker only uses public key N, e
    m_forged_int = (m1_int * m2_int) % N
    sig_forged   = (sig1 * sig2) % N

    # Verify forged sig actually works
    recovered = mod_exp(sig_forged, e, N)
    valid      = (recovered == m_forged_int)

    # Recover forged "message" bytes
    m_forged_bytes = m_forged_int.to_bytes(
        (m_forged_int.bit_length() + 7) // 8 or 1, 'big'
    )

    return {
        'm1_int':       str(m1_int),
        'm2_int':       str(m2_int),
        'm_forged_int': str(m_forged_int),
        'sig1':         str(sig1),
        'sig2':         str(sig2),
        'sig_forged':   str(sig_forged),
        'sig_forged_hex': hex(sig_forged),
        'recovered':    str(recovered),
        'forgery_valid': valid,
        'explanation': (
            f'σ_forged = σ₁ · σ₂ mod N = {sig1} · {sig2} mod N = {sig_forged}.\n'
            f'(σ_forged)^e mod N = {recovered} = m₁·m₂ mod N = {m_forged_int}.\n'
            f'Valid without private key: {valid}.'
        ),
    }


# ── 4. Sign-and-Verify Full Demo ───────────────────────────────────────────────

def sign_verify_demo(pk: dict, sk: dict, message: str) -> dict:
    """
    Full sign-and-verify demo returning rich intermediate values.

    Returns:
      - message, hash (hex), signature (hex/int)
      - verify steps: sigma^e mod N, hash of message, match
      - tamper result: flipping one bit of message bytes breaks verification
      - raw RSA comparison (no hash — shows it's vulnerable)
    """
    m_bytes = message.encode('utf-8')
    N, e, d = pk['N'], pk['e'], sk['d']
    k       = _modulus_byte_len(N)

    # ── Hash-then-sign ──────────────────────────────────────────────────
    h_int   = _sha256_int(m_bytes) % N
    h_hex   = hex(h_int)
    sigma   = mod_exp(h_int, d, N)

    # Verify step by step
    recovered = mod_exp(sigma, e, N)
    valid     = (recovered == h_int)

    # ── Tamper: flip bit 0 of last byte ────────────────────────────────
    tampered  = bytearray(m_bytes)
    tampered[-1] ^= 0x01
    tampered_str = tampered.decode('utf-8', errors='replace')
    h_tampered   = _sha256_int(bytes(tampered)) % N
    tamper_valid = (mod_exp(sigma, e, N) == h_tampered)

    # ── Raw RSA sign (no hash) ──────────────────────────────────────────
    m_int = int.from_bytes(m_bytes, 'big') % N
    sigma_raw      = mod_exp(m_int, d, N)
    recovered_raw  = mod_exp(sigma_raw, e, N)
    valid_raw      = (recovered_raw == m_int)

    return {
        'message':        message,
        'm_bytes_hex':    m_bytes.hex(),
        'hash_hex':       h_hex,
        'hash_int':       str(h_int),
        'sigma':          str(sigma),
        'sigma_hex':      hex(sigma),
        'recovered':      str(recovered),
        'verified':       valid,
        'tampered_message': tampered_str,
        'tampered_valid': tamper_valid,
        'raw': {
            'm_int':      str(m_int),
            'sigma_raw':  str(sigma_raw),
            'sigma_raw_hex': hex(sigma_raw),
            'recovered_raw': str(recovered_raw),
            'valid_raw':  valid_raw,
        },
    }


# ── 5. EUF-CMA Game ───────────────────────────────────────────────────────────

def euf_cma_game(pk: dict, sk: dict, n_sign_queries: int = 50) -> dict:
    """
    EUF-CMA (Existential Unforgeability under Chosen-Message Attack) game.

    Adversary strategy:
     - Can query the signing oracle for up to n_sign_queries messages.
     - Must then produce (m*, σ*) for an m* NOT in the query set.

    We simulate the adversary trying several strategies:
      1. Replay attack: re-use a signature from the oracle (should fail — m* must be NEW).
      2. Random guess: pick a random σ* for a new m*.
      3. Multiplicative forgery on raw-signed messages.

    Returns:
      - oracle_queries (list of signed messages)
      - adversary attempts + results (all should fail for hash-then-sign)
    """
    oracle = {}  # message -> signature (hash-then-sign)
    oracle_raw = {}  # message -> raw signature (for forgery attempt)

    # ── Build oracle ────────────────────────────────────────────────────
    vocab = [f"msg_{i:04d}" for i in range(n_sign_queries)]
    for m in vocab:
        oracle[m]     = sign(sk, m)
        oracle_raw[m] = sign_raw(sk, m.encode())

    signed_list = [{'message': m, 'sigma_hex': hex(oracle[m])} for m in vocab[:10]]

    # ── Adversary attempt 1: random guess ──────────────────────────────
    new_m    = "FORGED_MESSAGE_NEVER_SIGNED"
    rand_sig = _sec.randbelow(pk['N'])
    attempt1_valid = verify(pk, new_m, rand_sig)

    # ── Adversary attempt 2: piggyback an oracle sig on new msg ────────
    # Try sigma from msg_0000 on msg_9999 (different message)
    wrong_sig  = oracle[vocab[0]]
    attempt2_valid = verify(pk, vocab[-1] + "_modified", wrong_sig)

    # ── Adversary attempt 3: multiplicative forgery on raw oracle ──────
    m1k, m2k = vocab[0], vocab[1]
    m1b, m2b = m1k.encode(), m2k.encode()
    sig1_raw  = oracle_raw[m1k]
    sig2_raw  = oracle_raw[m2k]
    forgery   = multiplicative_forgery(pk, m1b, sig1_raw, m2b, sig2_raw)

    # Now check if that forged raw sig passes the HASH-THEN-SIGN verifier
    # (it won't, because hash-then-sign breaks the homomorphism)
    N = pk['N']
    m_forged_int = (int.from_bytes(m1b, 'big') % N * int.from_bytes(m2b, 'big') % N) % N
    m_forged_bytes = m_forged_int.to_bytes(max((m_forged_int.bit_length() + 7) // 8, 1), 'big')
    sig_forged_raw = (sig1_raw * sig2_raw) % N
    # Does the forged raw sig verify against hash-then-sign scheme?
    attempt3_valid_hash = verify(pk, m_forged_bytes, sig_forged_raw)
    # Does it verify against raw scheme? (Yes, demonstrating raw is broken)
    attempt3_valid_raw  = forgery['forgery_valid']

    return {
        'n_sign_queries': n_sign_queries,
        'signed_sample': signed_list,
        'attempts': [
            {
                'strategy':    'Random guess σ for unseen m',
                'message':     new_m,
                'sigma_hex':   hex(rand_sig),
                'valid':       attempt1_valid,
                'explanation': 'Adversary picks random σ — negligible probability of matching SHA256(m)^d',
            },
            {
                'strategy':    'Replay σ from oracle on different m',
                'message':     vocab[-1] + '_modified',
                'sigma_hex':   hex(wrong_sig),
                'valid':       attempt2_valid,
                'explanation': 'Signature bound to hash of original m — fails on any other message',
            },
            {
                'strategy':    'Multiplicative forgery (raw RSA)',
                'message_forged_hex': hex(m_forged_int),
                'sigma_forged_hex': hex(sig_forged_raw),
                'valid_raw_scheme':  attempt3_valid_raw,
                'valid_hash_scheme': attempt3_valid_hash,
                'explanation': (
                    'Forgery works on raw-RSA (no hash): σ₁·σ₂ is a valid sig on m₁·m₂ mod N. '
                    'But hash-then-sign BLOCKS this: H(m₁·m₂) ≠ H(m₁)·H(m₂) mod N.'
                ),
            },
        ],
        'conclusion': (
            'All adversary attempts FAIL against hash-then-sign RSA. '
            'EUF-CMA security holds because SHA-256 is a collision-resistant hash. '
            'Raw RSA (no hash) is broken by the multiplicative forgery.'
        ),
    }


# ── 6. Key + Full Pipeline ─────────────────────────────────────────────────────

def full_demo(bits: int = 512, message: str = 'Hello, RSA Signatures!') -> dict:
    """Generate fresh RSA keys and run the complete sign/verify demo."""
    t0          = time.perf_counter()
    pk, sk, aux = rsa_keygen(bits)
    keygen_ms   = round((time.perf_counter() - t0) * 1000, 2)

    demo = sign_verify_demo(pk, sk, message)

    return {
        'pk':      pk,
        'sk':      sk,
        'aux':     aux,
        'keygen_ms': keygen_ms,
        **demo,
    }
