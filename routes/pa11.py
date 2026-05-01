"""
PA #11 — Diffie-Hellman Key Exchange  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from crypto.pa11_dh import (
    gen_dh_params,
    run_dh_exchange,
    mitm_demo,
    cdh_brute_force,
    dh_alice_step1,
    dh_bob_step1,
    mod_exp,
)

router = APIRouter(prefix="/pa11", tags=["PA11"])
_executor = ThreadPoolExecutor(max_workers=4)


# ── Request / Response models ─────────────────────────────────────────────────

class GenParamsRequest(BaseModel):
    bits: int = Field(32, ge=16, le=64,
                      description="Bit-size of safe prime p (16–64 for instant demo, "
                                  "32 is toy, 64 is still fast)")


class ExchangeRequest(BaseModel):
    p: str = Field(..., description="Safe prime p (decimal string)")
    q: str = Field(..., description="Order q = (p-1)/2 (decimal string)")
    g: str = Field(..., description="Generator g (decimal string)")
    a: Optional[str] = Field(None, description="Alice's private exponent (decimal string, optional)")
    b: Optional[str] = Field(None, description="Bob's private exponent (decimal string, optional)")


class MITMRequest(BaseModel):
    p: str
    q: str
    g: str
    a: Optional[str] = None
    b: Optional[str] = None


class CDHRequest(BaseModel):
    p: str
    q: str
    g: str
    A: str   # g^a mod p
    B: str   # g^b mod p
    max_steps: int = Field(2**20, ge=1, le=2**22)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _s(v) -> str:
    """Serialize any big int to string to preserve JS precision."""
    return str(v)


def _ser_params(d: dict) -> dict:
    """Stringify the standard p/q/g/A/B/K fields for JSON safety."""
    out = {}
    for k, v in d.items():
        if isinstance(v, int):
            out[k] = str(v)
        elif isinstance(v, dict):
            out[k] = _ser_params(v)
        elif isinstance(v, bool):
            out[k] = v
        else:
            out[k] = v
    return out


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/gen-params")
async def generate_params(req: GenParamsRequest):
    """
    Generate DH group parameters: safe prime p = 2q+1 and generator g.
    Uses PA #13 Miller-Rabin for primality testing of both q and p.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: gen_dh_params(req.bits)
        )
        return _ser_params(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/exchange")
async def run_exchange(req: ExchangeRequest):
    """
    Run a full DH exchange between Alice and Bob.
    If a/b are provided they are used; otherwise random exponents are generated.
    Returns full transcript with all intermediate values.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        a = int(req.a) if req.a else None
        b = int(req.b) if req.b else None
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid integer: {e}")

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: run_dh_exchange(p, q, g, a, b)
        )
        return _ser_params(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/mitm")
async def run_mitm(req: MITMRequest):
    """
    MITM attack demo: Eve intercepts A and B, substitutes g^e for both,
    establishing separate shared secrets with Alice and Bob.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        a = int(req.a) if req.a else None
        b = int(req.b) if req.b else None
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid integer: {e}")

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: mitm_demo(p, q, g, a, b)
        )
        return _ser_params(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cdh-brute")
async def run_cdh_brute(req: CDHRequest):
    """
    CDH hardness demo: given g^a and g^b, recover a by brute-force DLP and
    compute g^(ab). Only feasible for small q (≤ 2^20 steps).
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        A, B = int(req.A), int(req.B)
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid integer: {e}")

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor,
            lambda: cdh_brute_force(p, q, g, A, B, req.max_steps)
        )
        return _ser_params(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/toy-params")
def get_toy_params():
    """
    Return pre-generated, verified 32-bit safe-prime DH parameters for instant
    demo use (no generation wait).  All values verified by PA #13 Miller-Rabin.

    p = 3163465259  (32-bit safe prime)
    q = 1581732629  (Sophie Germain prime, q = (p-1)/2)
    g = 2873556259  (generator of the prime-order subgroup of order q)
    Verified: miller_rabin(p,40)=PRIME, miller_rabin(q,40)=PRIME, g^q ≡ 1 (mod p)
    """
    return {
        "p": "3163465259",
        "q": "1581732629",
        "g": "2873556259",
        "bits": 32,
        "note": "Pre-generated verified 32-bit safe prime. q=(p-1)/2 is also prime. "
                "Generated by gen_dh_params(32) and tested with PA#13 Miller-Rabin.",
    }
