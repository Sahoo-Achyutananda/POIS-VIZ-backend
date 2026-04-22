"""
PA #16 — ElGamal Public-Key Cryptosystem  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from crypto.pa16_elgamal import (
    elgamal_keygen, elgamal_enc, elgamal_dec,
    elgamal_malleability, ind_cpa_game, ind_cca_failure,
    ind_cpa_small_group_attack, ind_cca_multi_round,
    elgamal_full_demo,
)
from crypto.pa11_dh import gen_dh_params

router    = APIRouter(prefix="/pa16", tags=["PA16"])
_executor = ThreadPoolExecutor(max_workers=4)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ser(d):
    if isinstance(d, dict):
        return {k: _ser(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_ser(i) for i in d]
    if isinstance(d, int) and not isinstance(d, bool):
        return str(d)
    return d


# ── Request Models ─────────────────────────────────────────────────────────────

class ParamsRequest(BaseModel):
    bits: int = Field(32, ge=8, le=128)

class KeygenRequest(BaseModel):
    p: str; q: str; g: str

class EncRequest(BaseModel):
    p: str; q: str; g: str; h: str; m: str

class DecRequest(BaseModel):
    p: str; x: str; c1: str; c2: str

class MalleabilityRequest(BaseModel):
    p: str; q: str; g: str; h: str; x: str
    m: str
    lam: int = Field(2, ge=2, le=100)

class INDCPARequest(BaseModel):
    p: str; q: str; g: str
    n_rounds: int = Field(50, ge=10, le=200)

class INDCPASmallRequest(BaseModel):
    p: str; q: str; g: str
    n_rounds: int = Field(30, ge=5, le=100)

class INDCCARequest(BaseModel):
    p: str; q: str; g: str

class INDCCAMultiRequest(BaseModel):
    p: str; q: str; g: str
    n_rounds: int = Field(20, ge=5, le=50)

class FullDemoRequest(BaseModel):
    bits: int = Field(32, ge=16, le=128)
    message_int: Optional[str] = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/gen-params")
async def gen_params(req: ParamsRequest):
    """Generate a safe-prime DH group (p=2q+1) for ElGamal."""
    loop = asyncio.get_running_loop()
    try:
        params = await loop.run_in_executor(_executor, lambda: gen_dh_params(req.bits))
        return _ser(params)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/keygen")
async def keygen(req: KeygenRequest):
    """ElGamal key generation: x ← Zq, h = g^x mod p."""
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        x, h = await loop.run_in_executor(_executor, lambda: elgamal_keygen(p, q, g))
        return _ser({'x': x, 'h': h, 'h_hex': hex(h)})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/encrypt")
async def encrypt(req: EncRequest):
    """ElGamal encryption: C = (g^r, m·h^r) with fresh r ← Zq."""
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        h, m    = int(req.h), int(req.m)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        c1, c2 = await loop.run_in_executor(_executor, lambda: elgamal_enc(p, q, g, h, m))
        return _ser({'c1': c1, 'c2': c2, 'c1_hex': hex(c1), 'c2_hex': hex(c2)})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/decrypt")
async def decrypt(req: DecRequest):
    """ElGamal decryption: m = c2 · c1^(-x) mod p."""
    try:
        p, x, c1, c2 = int(req.p), int(req.x), int(req.c1), int(req.c2)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        m = await loop.run_in_executor(_executor, lambda: elgamal_dec(p, x, c1, c2))
        return _ser({'m': m, 'm_hex': hex(m)})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/malleability")
async def malleability(req: MalleabilityRequest):
    """
    Malleability demo: (c1, λ·c2) decrypts to λ·m.
    Demonstrates ElGamal is NOT IND-CCA secure.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        h, x, m = int(req.h), int(req.x), int(req.m)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: elgamal_malleability(p, q, g, h, x, m, req.lam)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/ind-cpa-game")
async def run_ind_cpa(req: INDCPARequest):
    """
    IND-CPA security game: adversary tries to distinguish encryptions.
    Both dumb and smart strategies win ≈ 50% — confirming IND-CPA security.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ind_cpa_game(p, q, g, req.n_rounds)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/ind-cca-failure")
async def run_ind_cca(req: INDCCARequest):
    """
    IND-CCA failure demo: malleability lets adversary win the CCA game.
    Adversary queries (c1*, 2·c2*) → gets 2·m_b → recovers m_b → wins.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ind_cca_failure(p, q, g)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/ind-cpa-small-attack")
async def run_ind_cpa_small(req: INDCPASmallRequest):
    """
    IND-CPA distinguisher on a tiny group (q ≈ 2^10).
    Brute-forces DLP to recover r → decrypt deterministically.
    Advantage ≈ 1.0 for small q; ≈ 0.0 for large (DDH-hard) q.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ind_cpa_small_group_attack(p, q, g, req.n_rounds)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/ind-cca-multi")
async def run_ind_cca_multi(req: INDCCAMultiRequest):
    """
    Run the deterministic CCA2 oracle attack for N rounds.
    Counts wins — should be 100%, proving ElGamal is NOT IND-CCA2 secure.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ind_cca_multi_round(p, q, g, req.n_rounds)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def full_demo(req: FullDemoRequest):
    """One-shot: generate group, key, encrypt, decrypt — full transcript."""
    loop = asyncio.get_running_loop()
    try:
        m_int = int(req.message_int) if req.message_int else None
        result = await loop.run_in_executor(
            _executor, lambda: elgamal_full_demo(req.bits, m_int)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
