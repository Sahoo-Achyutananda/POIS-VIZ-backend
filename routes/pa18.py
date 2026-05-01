"""
PA #18 — Oblivious Transfer  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from crypto.pa18_ot import (
    ot_receiver_step1, ot_sender_step, ot_receiver_step2,
    ot_correctness_test, receiver_privacy_demo, sender_privacy_demo,
    ot_run, ot_full_demo,
)
from crypto.pa11_dh import gen_dh_params

router    = APIRouter(prefix="/pa18", tags=["PA18"])
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


# ── Models ────────────────────────────────────────────────────────────────────

class GenParamsRequest(BaseModel):
    bits: int = Field(32, ge=16, le=64)

class Step1Request(BaseModel):
    p: str; q: str; g: str
    b: int = Field(..., ge=0, le=1)

class Step2Request(BaseModel):
    p: str; q: str; g: str
    pk0_h: str; pk1_h: str
    m0: str; m1: str

class Step3Request(BaseModel):
    p: str
    b: int = Field(..., ge=0, le=1)
    x_b: str
    c1_0: str; c2_0: str   # C0
    c1_1: str; c2_1: str   # C1

class OTRunRequest(BaseModel):
    p: str; q: str; g: str
    b: int = Field(..., ge=0, le=1)
    m0: str; m1: str

class CorrectnesRequest(BaseModel):
    p: str; q: str; g: str
    n_trials: int = Field(50, ge=10, le=200)

class PrivacyRequest(BaseModel):
    p: str; q: str; g: str

class SenderPrivacyRequest(BaseModel):
    p: str; q: str; g: str
    m0: str; m1: str
    b: int = Field(..., ge=0, le=1)
    max_brute: int = Field(500, ge=10, le=2000)

class FullDemoRequest(BaseModel):
    bits: int   = Field(32, ge=16, le=64)
    b:    int   = Field(0, ge=0, le=1)
    m0:   int   = Field(42, ge=2)
    m1:   int   = Field(99, ge=2)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/gen-params")
async def gen_params(req: GenParamsRequest):
    """Generate a safe-prime DH group for use in all OT steps."""
    loop = asyncio.get_running_loop()
    try:
        params = await loop.run_in_executor(_executor, lambda: gen_dh_params(req.bits))
        return _ser(params)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/receiver-step1")
async def receiver_step1(req: Step1Request):
    """
    OT_Receiver_Step1(b) → (pk0, pk1, state)

    Generates pk_b honestly and pk_{1-b} without a trapdoor.
    Returns both public keys + private state (x_b) needed for Step 3.
    """
    try:
        p, q, g, b = int(req.p), int(req.q), int(req.g), req.b
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        pk0, pk1, state = await loop.run_in_executor(
            _executor, lambda: ot_receiver_step1(p, q, g, b)
        )
        return _ser({'pk0_h': pk0['h'], 'pk1_h': pk1['h'],
                     'x_b': state['x_b'], 'honest_key': b})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/sender-step")
async def sender_step(req: Step2Request):
    """
    OT_Sender_Step(pk0, pk1, m0, m1) → (C0, C1)

    Encrypts each message under the corresponding public key.
    Both ciphertexts are sent to the receiver.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        pk0  = {'h': int(req.pk0_h)}
        pk1  = {'h': int(req.pk1_h)}
        m0, m1 = int(req.m0), int(req.m1)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        C0, C1 = await loop.run_in_executor(
            _executor, lambda: ot_sender_step(p, q, g, pk0, pk1, m0, m1)
        )
        return _ser({'C0': {'c1': C0[0], 'c2': C0[1]},
                     'C1': {'c1': C1[0], 'c2': C1[1]}})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/receiver-step2")
async def receiver_step2(req: Step3Request):
    """
    OT_Receiver_Step2(state, C0, C1) → m_b

    Decrypts only C_b. C_{1-b} is untouched.
    """
    try:
        p   = int(req.p)
        b   = req.b
        x_b = int(req.x_b)
        C0 = (int(req.c1_0), int(req.c2_0))
        C1 = (int(req.c1_1), int(req.c2_1))
        state = {'b': b, 'x_b': x_b, 'p': p, 'q': 0, 'g': 0}
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        m = await loop.run_in_executor(
            _executor, lambda: ot_receiver_step2(state, C0, C1)
        )
        return _ser({'m_received': m, 'm_hidden': '??'})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/ot-run")
async def run_ot(req: OTRunRequest):
    """
    Single full OT execution with all intermediate values for the step-by-step UI.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        m0, m1  = int(req.m0), int(req.m1)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ot_run(p, q, g, req.b, m0, m1)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/correctness")
async def correctness(req: CorrectnesRequest):
    """
    Run n_trials OT instances, verify receiver always gets m_b.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ot_correctness_test(p, q, g, req.n_trials)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/receiver-privacy")
async def recv_privacy(req: PrivacyRequest):
    """
    Demonstrate sender cannot determine b from (pk0, pk1).
    Both keys are statistically close to uniform under DDH.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: receiver_privacy_demo(p, q, g)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/sender-privacy")
async def send_privacy(req: SenderPrivacyRequest):
    """
    Demonstrate receiver cannot decrypt C_{1-b}.
    Cheat attempt: brute-force DLP on h_{1-b} — fails for proper group sizes.
    """
    try:
        p, q, g = int(req.p), int(req.q), int(req.g)
        m0, m1  = int(req.m0), int(req.m1)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=str(ex))
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: sender_privacy_demo(
                p, q, g, m0, m1, req.b, req.max_brute)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def full_demo(req: FullDemoRequest):
    """
    One-shot: generate group, run OT, 50-trial correctness test,
    receiver-privacy demo, sender-privacy cheat attempt.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: ot_full_demo(req.bits, req.b, req.m0, req.m1)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
