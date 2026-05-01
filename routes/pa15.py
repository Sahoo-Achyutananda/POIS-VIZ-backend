"""
PA #15 — Digital Signatures  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Literal

from crypto.pa15_signatures import (
    sign, verify,
    sign_raw, verify_raw,
    multiplicative_forgery,
    sign_verify_demo,
    euf_cma_game,
    full_demo,
)
from crypto.pa12_rsa import rsa_keygen

router    = APIRouter(prefix="/pa15", tags=["PA15"])
_executor = ThreadPoolExecutor(max_workers=4)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ser(d):
    """Recursively stringify ints to preserve JS precision."""
    if isinstance(d, dict):
        return {k: _ser(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_ser(i) for i in d]
    if isinstance(d, int) and not isinstance(d, bool):
        return str(d)
    return d


# ── Request Models ─────────────────────────────────────────────────────────────

class KeygenRequest(BaseModel):
    bits: int = Field(512, ge=64, le=2048)


class SignRequest(BaseModel):
    N:       str = Field(..., description="RSA modulus (decimal string)")
    d:       str = Field(..., description="Private exponent (decimal string)")
    message: str = Field(..., description="Message to sign (UTF-8)")
    mode:    Literal['hash', 'raw'] = Field('hash')


class VerifyRequest(BaseModel):
    N:       str
    e:       str
    message: str
    sigma:   str
    mode:    Literal['hash', 'raw'] = Field('hash')


class TamperRequest(BaseModel):
    N:       str
    e:       str
    message: str
    sigma:   str


class ForgeryRequest(BaseModel):
    N:   str
    e:   str
    m1:  str = Field(..., description="First message (UTF-8)")
    m2:  str = Field(..., description="Second message (UTF-8)")
    sig1: str = Field(..., description="Raw RSA sig on m1 (decimal string)")
    sig2: str = Field(..., description="Raw RSA sig on m2 (decimal string)")


class EUFCMARequest(BaseModel):
    bits:          int = Field(256, ge=64, le=512)
    n_sign_queries: int = Field(20, ge=5, le=50)


class FullDemoRequest(BaseModel):
    bits:    int = Field(512, ge=64, le=1024)
    message: str = Field("Hello, RSA Signatures!")


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/keygen")
async def generate_keys(req: KeygenRequest):
    """Generate an RSA key pair for signing."""
    loop = asyncio.get_running_loop()
    try:
        pk, sk, aux = await loop.run_in_executor(_executor, lambda: rsa_keygen(req.bits))
        return _ser({'pk': pk, 'sk': sk, 'aux': aux})
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/sign")
async def sign_message(req: SignRequest):
    """
    Sign a message.
    mode='hash': σ = SHA256(m)^d mod N  (secure hash-then-sign)
    mode='raw':  σ = m^d mod N          (insecure textbook sign — for forgery demo)

    Returns sigma plus all intermediate values for the Sign/Verify visualiser.
    """
    try:
        N, d = int(req.N), int(req.d)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))

    sk = {'N': N, 'd': d}
    m_bytes = req.message.encode('utf-8')

    loop = asyncio.get_running_loop()
    try:
        from crypto.sha256_pure import PureSHA256
        from crypto.pa13_miller_rabin import mod_exp

        def _run():
            if req.mode == 'hash':
                h_raw = int.from_bytes(PureSHA256(m_bytes).digest(), 'big')
                h_int = h_raw % N
                sigma = mod_exp(h_int, d, N)
                return {
                    'sigma':       sigma,
                    'sigma_hex':   hex(sigma),
                    'mode':        'hash',
                    'm_bytes_hex': m_bytes.hex(),
                    'hash_raw_hex': hex(h_raw),   # SHA256(m) before mod N
                    'hash_int':    str(h_int),    # SHA256(m) mod N
                    'hash_hex':    hex(h_int),
                    'step_m':      repr(req.message),
                    'step_h':      hex(h_int),
                    'step_s':      hex(sigma),
                }
            else:
                sigma = sign_raw(sk, m_bytes)
                m_int = int.from_bytes(m_bytes, 'big') % N
                return {
                    'sigma':       sigma,
                    'sigma_hex':   hex(sigma),
                    'mode':        'raw',
                    'm_bytes_hex': m_bytes.hex(),
                    'm_int':       str(m_int),
                    'm_int_hex':   hex(m_int),
                }

        result = await loop.run_in_executor(_executor, _run)
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/verify")
async def verify_signature(req: VerifyRequest):
    """
    Verify a signature and return ALL intermediate values for visualisation:
      - m_bytes_hex              : message as hex bytes
      - hash_of_msg / m_int_hex  : the value the verifier computes from the message
      - recovered                : σ^e mod N  (what the verifier derives from the signature)
      - match                    : recovered == hash_of_msg  (the equality check)
      - valid                    : overall boolean result
    """
    try:
        N, e, sigma = int(req.N), int(req.e), int(req.sigma)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))

    m_bytes = req.message.encode('utf-8')

    loop = asyncio.get_running_loop()
    try:
        from crypto.sha256_pure import PureSHA256
        from crypto.pa13_miller_rabin import mod_exp

        def _run():
            recovered = mod_exp(sigma, e, N)   # σ^e mod N
            if req.mode == 'hash':
                h_raw = int.from_bytes(PureSHA256(m_bytes).digest(), 'big')
                h_int = h_raw % N              # SHA256(m) mod N
                match = (recovered == h_int)
                return {
                    'valid':          match,
                    'mode':           'hash',
                    # intermediates
                    'm_bytes_hex':    m_bytes.hex(),
                    'hash_raw_hex':   hex(h_raw),
                    'hash_of_msg':    hex(h_int),    # SHA256(m) mod N
                    'recovered':      hex(recovered), # σ^e mod N
                    'match':          match,
                    # step labels
                    'step1_label':    'm (bytes) → SHA256 → mod N',
                    'step1_value':    hex(h_int),
                    'step2_label':    'σ^e mod N  (signature opened)',
                    'step2_value':    hex(recovered),
                    'step3_label':    'SHA256(m) mod N  ==  σ^e mod N ?',
                    'step3_value':    str(match),
                }
            else:
                m_int = int.from_bytes(m_bytes, 'big') % N
                match = (recovered == m_int)
                return {
                    'valid':          match,
                    'mode':           'raw',
                    'm_bytes_hex':    m_bytes.hex(),
                    'm_int_hex':      hex(m_int),
                    'recovered':      hex(recovered),
                    'match':          match,
                    'step1_label':    'm (bytes)  as integer mod N',
                    'step1_value':    hex(m_int),
                    'step2_label':    'σ^e mod N  (signature opened)',
                    'step2_value':    hex(recovered),
                    'step3_label':    'm_int  ==  σ^e mod N ?',
                    'step3_value':    str(match),
                }

        result = await loop.run_in_executor(_executor, _run)
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/tamper-demo")
async def tamper_demo(req: TamperRequest):
    """
    Demonstrate that flipping one bit of the message invalidates the signature.
    Returns both the original verification and the tampered verification.
    """
    try:
        N, e, sigma = int(req.N), int(req.e), int(req.sigma)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))

    vk = {'N': N, 'e': e}
    m_bytes = req.message.encode('utf-8')
    tampered = bytearray(m_bytes)
    tampered[-1] ^= 0x01   # flip LSB of last byte

    loop = asyncio.get_running_loop()
    try:
        orig_valid  = await loop.run_in_executor(_executor, lambda: verify(vk, m_bytes, sigma))
        tamp_valid  = await loop.run_in_executor(_executor, lambda: verify(vk, bytes(tampered), sigma))
        return _ser({
            'original_message':  req.message,
            'tampered_message':  tampered.decode('utf-8', errors='replace'),
            'tampered_hex':      tampered.hex(),
            'sigma':             sigma,
            'original_valid':    orig_valid,
            'tampered_valid':    tamp_valid,
        })
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/forgery-demo")
async def forgery_demo(req: ForgeryRequest):
    """
    Multiplicative forgery on raw RSA (no hash).
    Given σ₁ = m₁^d mod N  and  σ₂ = m₂^d mod N,
    forge σ = (σ₁·σ₂) mod N — valid for m = m₁·m₂ mod N, no private key.
    """
    try:
        N, e    = int(req.N), int(req.e)
        sig1, sig2 = int(req.sig1), int(req.sig2)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))

    vk = {'N': N, 'e': e}
    m1b, m2b = req.m1.encode(), req.m2.encode()

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: multiplicative_forgery(vk, m1b, sig1, m2b, sig2)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/euf-cma-game")
async def run_euf_cma(req: EUFCMARequest):
    """
    EUF-CMA Security Game.
    Generates RSA keys, lets adversary make signing queries, then attempts to forge.
    All forgery attempts fail (demonstrating EUF-CMA security of hash-then-sign).
    """
    loop = asyncio.get_running_loop()
    try:
        def _run():
            pk, sk, aux = rsa_keygen(req.bits)
            return euf_cma_game(pk, sk, req.n_sign_queries), pk, aux

        result, pk, aux = await loop.run_in_executor(_executor, _run)
        return _ser({**result, 'pk': pk, 'aux': aux})
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def run_full_demo(req: FullDemoRequest):
    """
    One-shot: generate keys, sign a message, verify, tamper demo, raw sign comparison.
    Returns all intermediate hash values and step-by-step verification.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: full_demo(req.bits, req.message)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
