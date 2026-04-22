"""
PA #17 — CCA-Secure PKC via Encrypt-then-Sign  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from crypto.pa17_signcrypt import (
    signcrypt, unsigncrypt,
    ind_cca2_game, malleability_contrast, full_demo,
)
from crypto.pa11_dh import gen_dh_params
from crypto.pa12_rsa import rsa_keygen
from crypto.pa16_elgamal import elgamal_keygen

router    = APIRouter(prefix="/pa17", tags=["PA17"])
_executor = ThreadPoolExecutor(max_workers=4)


# ── Serialisation helper ───────────────────────────────────────────────────────

def _ser(d):
    if isinstance(d, dict):
        return {k: _ser(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_ser(i) for i in d]
    if isinstance(d, int) and not isinstance(d, bool):
        return str(d)
    return d


# ── Request models ─────────────────────────────────────────────────────────────

class SigncryptRequest(BaseModel):
    # ElGamal public key
    p: str; q: str; g: str; h: str
    # RSA signing private key
    N: str; d: str
    # Plaintext (integer)
    m: str

class UnsigncryptRequest(BaseModel):
    # ElGamal private key
    p: str; x: str
    # RSA verification public key
    N: str; e: str
    # Ciphertext + signature
    c1: str; c2: str; sigma: str

class ContrastRequest(BaseModel):
    group_bits: int = Field(32, ge=16, le=64)
    rsa_bits:   int = Field(256, ge=128, le=512)
    m:          int = Field(42, ge=2)
    lam:        int = Field(2,  ge=2, le=100)

class CCA2GameRequest(BaseModel):
    n_rounds:   int = Field(20, ge=5, le=100)
    group_bits: int = Field(32, ge=16, le=64)
    rsa_bits:   int = Field(128, ge=64, le=512)

class FullDemoRequest(BaseModel):
    group_bits:  int = Field(32, ge=16, le=64)
    rsa_bits:    int = Field(256, ge=128, le=512)
    message_int: int = Field(1234, ge=2)

class SetupRequest(BaseModel):
    group_bits: int = Field(32, ge=16, le=64)
    rsa_bits:   int = Field(256, ge=128, le=512)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/setup")
async def setup_keys(req: SetupRequest):
    """
    Generate a fresh ElGamal group + key pair and RSA signing keys.
    Returns all public and private values for the demo.
    """
    loop = asyncio.get_running_loop()
    try:
        def _run():
            params = gen_dh_params(req.group_bits)
            p, q, g = params['p'], params['q'], params['g']
            enc_x, enc_h = elgamal_keygen(p, q, g)
            pk_rsa, sk_rsa, aux = rsa_keygen(req.rsa_bits)
            return {
                'group': {'p': p, 'q': q, 'g': g, 'bits': req.group_bits},
                'elgamal': {'pub_h': enc_h, 'priv_x': enc_x},
                'rsa': {
                    'pub_N': pk_rsa['N'], 'pub_e': pk_rsa['e'],
                    'priv_d': sk_rsa['d'],
                    'keygen_ms': aux.get('time_ms', 0),
                },
            }
        result = await loop.run_in_executor(_executor, _run)
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/signcrypt")
async def do_signcrypt(req: SigncryptRequest):
    """
    Encrypt-then-Sign:
      CE = ElGamal_enc(pk_enc, m)
      σ  = RSA_sign(sk_sign, encode(CE))
      return (CE, σ)
    """
    try:
        pk_enc = {'p': int(req.p), 'q': int(req.q), 'g': int(req.g), 'h': int(req.h)}
        sk_sign = {'N': int(req.N), 'd': int(req.d)}
        m = int(req.m)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(_executor,
                     lambda: signcrypt(pk_enc, sk_sign, m))
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/unsigncrypt")
async def do_unsigncrypt(req: UnsigncryptRequest):
    """
    Verify-then-Decrypt:
      1. Verify σ on encode(CE)  — reject with ⊥ if invalid
      2. Decrypt CE with ElGamal sk_enc
    """
    try:
        sk_enc  = {'p': int(req.p), 'x': int(req.x)}
        vk_sign = {'N': int(req.N), 'e': int(req.e)}
        c1, c2, sigma = int(req.c1), int(req.c2), int(req.sigma)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))

    loop = asyncio.get_running_loop()
    try:
        m, trace = await loop.run_in_executor(_executor,
                        lambda: unsigncrypt(sk_enc, vk_sign, c1, c2, sigma))
        return _ser({'decrypted': m, **trace})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/malleability-contrast")
async def malleability_demo(req: ContrastRequest):
    """
    Side-by-side contrast:
      - Plain ElGamal: tamper (c1, λ·c2) → oracle returns λ·m  (attack succeeds)
      - Encrypt-then-Sign: tamper same → Verify fails → ⊥  (attack blocked)
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(_executor,
                     lambda: malleability_contrast(
                         req.group_bits, req.rsa_bits, req.m, req.lam))
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/ind-cca2-game")
async def run_cca2_game(req: CCA2GameRequest):
    """
    IND-CCA2 game:
      Adversary has a decryption oracle.
      All tamper strategies return ⊥ → oracle useless → win rate ≈ 50%.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(_executor,
                     lambda: ind_cca2_game(req.n_rounds, req.group_bits, req.rsa_bits))
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def run_full_demo(req: FullDemoRequest):
    """
    Full lifecycle: keygen → signcrypt → correct decrypt → tamper → blocked.
    Returns all intermediate values for the frontend visualizer.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(_executor,
                     lambda: full_demo(req.group_bits, req.rsa_bits, req.message_int))
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
