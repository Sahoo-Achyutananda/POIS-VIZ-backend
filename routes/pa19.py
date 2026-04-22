"""
PA #19 — Secure AND, XOR, NOT Gates  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from crypto.pa19_secure_gates import (
    secure_and, secure_xor, secure_not,
    truth_table_test, full_demo, _gen_group,
)

router    = APIRouter(prefix="/pa19", tags=["PA19"])
_executor = ThreadPoolExecutor(max_workers=4)


# ── Serialisation ─────────────────────────────────────────────────────────────

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

class ANDRequest(BaseModel):
    p: str; q: str; g: str
    a: int = Field(..., ge=0, le=1)
    b: int = Field(..., ge=0, le=1)

class XORRequest(BaseModel):
    a: int = Field(..., ge=0, le=1)
    b: int = Field(..., ge=0, le=1)

class NOTRequest(BaseModel):
    a: int = Field(..., ge=0, le=1)

class TruthTableRequest(BaseModel):
    p: str; q: str; g: str
    trials_per_combo: int = Field(50, ge=5, le=200)

class FullDemoRequest(BaseModel):
    bits: int = Field(32, ge=16, le=64)
    a:    int = Field(1, ge=0, le=1)
    b:    int = Field(1, ge=0, le=1)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/gen-params")
async def gen_params(req: GenParamsRequest):
    """Generate a safe-prime DH group (shared by both parties)."""
    loop = asyncio.get_running_loop()
    try:
        params = await loop.run_in_executor(_executor, lambda: _gen_group(req.bits))
        return _ser(params)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/secure-and")
async def api_secure_and(req: ANDRequest):
    """
    Secure AND(a, b) via 1-out-of-2 OT (PA#18).
    Alice's OT messages: (m0=0, m1=a). Bob's choice: b.
    Bob receives m_b = a·b = a∧b.
    Returns full protocol trace + privacy analysis.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: secure_and(p, q, g, req.a, req.b)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/secure-xor")
async def api_secure_xor(req: XORRequest):
    """
    Secure XOR(a, b) via additive secret sharing over Z_2. Free — no OT.
    Alice samples r, sends r. Output = (a⊕r) ⊕ (b⊕r) = a⊕b.
    """
    try:
        result = secure_xor(req.a, req.b)
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/secure-not")
async def api_secure_not(req: NOTRequest):
    """
    Secure NOT(a): Alice locally flips her bit. No communication needed.
    """
    try:
        result = secure_not(req.a)
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/truth-table")
async def api_truth_table(req: TruthTableRequest):
    """
    Run all 4 input combinations (a,b) ∈ {00,01,10,11} for AND and XOR,
    across trials_per_combo runs each. Confirms 100% correctness.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: truth_table_test(p, q, g, req.trials_per_combo)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def api_full_demo(req: FullDemoRequest):
    """
    One-shot: generate group, run AND+XOR+NOT, run truth table (20 trials).
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: full_demo(req.bits, req.a, req.b)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
