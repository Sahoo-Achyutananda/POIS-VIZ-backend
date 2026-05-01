"""
PA #20 — 2-Party Secure Computation  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from crypto.pa20_mpc import (
    millionaires, secure_equality, secure_full_adder,
    correctness_sweep, full_demo,
)
from crypto.pa11_dh import gen_dh_params

router    = APIRouter(prefix="/pa20", tags=["PA20"])
_executor = ThreadPoolExecutor(max_workers=4)


def _ser(d):
    if isinstance(d, dict):
        return {k: _ser(v) for k, v in d.items()}
    if isinstance(d, (list, tuple)):
        return [_ser(i) for i in d]
    if isinstance(d, int) and not isinstance(d, bool):
        return str(d)
    return d


# ── Request models ────────────────────────────────────────────────────────────

class GenParamsRequest(BaseModel):
    bits: int = Field(32, ge=16, le=64)

class MillionairesRequest(BaseModel):
    p: str; q: str; g: str
    x: int = Field(..., ge=0, le=100)
    y: int = Field(..., ge=0, le=100)
    n_bits: int = Field(7, ge=1, le=7)

class EqualityRequest(BaseModel):
    p: str; q: str; g: str
    x: int = Field(..., ge=0, le=100)
    y: int = Field(..., ge=0, le=100)
    n_bits: int = Field(7, ge=1, le=7)

class AdderRequest(BaseModel):
    p: str; q: str; g: str
    a:   int = Field(..., ge=0, le=1)
    b:   int = Field(..., ge=0, le=1)
    cin: int = Field(0,  ge=0, le=1)

class SweepRequest(BaseModel):
    p: str; q: str; g: str
    n_bits: int = Field(2, ge=1, le=3)

class FullDemoRequest(BaseModel):
    bits: int = Field(32, ge=16, le=64)
    x:    int = Field(5,  ge=0, le=100)
    y:    int = Field(3,  ge=0, le=100)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/gen-params")
async def gen_params(req: GenParamsRequest):
    loop = asyncio.get_running_loop()
    try:
        params = await loop.run_in_executor(_executor, lambda: gen_dh_params(req.bits))
        return _ser(params)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/millionaires")
async def api_millionaires(req: MillionairesRequest):
    """
    Secure greater-than: Alice holds x, Bob holds y.
    Both learn (x > y) without revealing x or y.
    Uses n_bits AND gates per bit position via PA#19.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: millionaires(p, q, g, req.x, req.y, req.n_bits)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/equality")
async def api_equality(req: EqualityRequest):
    """
    Secure equality: both learn (x == y) without revealing x or y.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: secure_equality(p, q, g, req.x, req.y, req.n_bits)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/full-adder")
async def api_full_adder(req: AdderRequest):
    """
    Secure 1-bit full adder: both learn (sum, carry) from (a, b, cin).
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: secure_full_adder(p, q, g, req.a, req.b, req.cin)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/correctness-sweep")
async def api_sweep(req: SweepRequest):
    """
    Run all (x,y) combos for n_bits-bit inputs across all three circuits.
    Verify 100% correctness of the gate decomposition.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: correctness_sweep(p, q, g, req.n_bits)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def api_full_demo(req: FullDemoRequest):
    """One-shot: generate group, run all three circuits, return results."""
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: full_demo(req.bits, req.x, req.y)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
