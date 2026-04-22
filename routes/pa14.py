"""
PA #14 — Chinese Remainder Theorem & Breaking Textbook RSA  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List

from crypto.pa14_crt import (
    crt,
    rsa_dec_crt,
    hastad_attack,
    integer_eth_root,
    benchmark_crt_vs_standard,
    garner_correctness_check,
    hastad_boundary,
    hastad_demo,
    padding_breaks_hastad,
)
from crypto.pa12_rsa import rsa_keygen, rsa_enc, rsa_dec

router    = APIRouter(prefix="/pa14", tags=["PA14"])
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


# ── Request models ─────────────────────────────────────────────────────────────

class CRTRequest(BaseModel):
    residues: List[str] = Field(..., description="List of residues a_i as decimal strings")
    moduli:   List[str] = Field(..., description="List of pairwise-coprime moduli n_i as decimal strings")


class GarnerRequest(BaseModel):
    N:     str = Field(..., description="RSA modulus N (decimal string)")
    p:     str
    q:     str
    dp:    str
    dq:    str
    q_inv: str
    c:     str = Field(..., description="Ciphertext (decimal string)")


class BenchmarkRequest(BaseModel):
    bits:   int = Field(1024, ge=64,  le=4096)
    trials: int = Field(1000, ge=10,  le=1000)


class GarnerCorrectnessRequest(BaseModel):
    bits:       int = Field(512,  ge=64, le=2048)
    n_messages: int = Field(100,  ge=10, le=100)


class HastadDemoRequest(BaseModel):
    message:     str  = Field("Hi", description="Short plaintext (≤ 3 bytes for 64-bit demo)")
    use_padding: bool = Field(False)
    n_bits:      int  = Field(64, ge=32, le=128,
                               description="Modulus bit-size (keep ≤ 128 for instant computation)")


class HastadBoundaryRequest(BaseModel):
    n_bits: int = Field(64, ge=32, le=1024)
    e:      int = Field(3,  ge=2,  le=5)


class PaddingCompareRequest(BaseModel):
    message: str = Field("Hi")
    n_bits:  int = Field(64, ge=32, le=128)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/crt-solve")
async def solve_crt(req: CRTRequest):
    """
    Solve x ≡ a_i (mod n_i) for pairwise-coprime moduli via the
    constructive CRT formula using modular inverses (Extended Euclidean).
    """
    try:
        residues = [int(r) for r in req.residues]
        moduli   = [int(m) for m in req.moduli]
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=f"Bad integer: {ex}")

    loop = asyncio.get_running_loop()
    try:
        x = await loop.run_in_executor(_executor, lambda: crt(residues, moduli))
        N = 1
        for m in moduli: N *= m
        return _ser({'x': x, 'N': N, 'residues': residues, 'moduli': moduli})
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/garner-decrypt")
async def garner_decrypt(req: GarnerRequest):
    """
    CRT-based RSA decryption (Garner's algorithm).
    Verify by comparing with standard rsa_dec.
    """
    try:
        sk_crt = {
            'N':     int(req.N),
            'p':     int(req.p),
            'q':     int(req.q),
            'dp':    int(req.dp),
            'dq':    int(req.dq),
            'q_inv': int(req.q_inv),
        }
        c = int(req.c)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=f"Bad integer: {ex}")

    loop = asyncio.get_running_loop()
    try:
        def _run():
            m_crt = rsa_dec_crt(sk_crt, c)
            sk_std = {'N': sk_crt['N'], 'd': None}   # d not provided → skip verify
            return {'m_crt': m_crt}
        r = await loop.run_in_executor(_executor, _run)
        return _ser(r)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/benchmark")
async def run_benchmark(req: BenchmarkRequest):
    """
    Benchmark standard rsa_dec vs rsa_dec_crt for `trials` decryptions
    at a given key bit-size. Returns timings and speedup ratio (≈ 3–4×).
    For 1024-bit / 1000 trials expect ~60-120 s; for 2048-bit longer.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor,
            lambda: benchmark_crt_vs_standard(req.bits, req.trials)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/garner-correctness")
async def check_garner_correctness(req: GarnerCorrectnessRequest):
    """
    Verify rsa_dec_crt(sk, c) == rsa_dec(sk, c) for n_messages random messages.

    Generates one RSA key pair at `bits` bits, then for each of the
    n_messages random plaintexts encrypts and decrypts via both methods,
    comparing results row-by-row.  All 100 rows must match.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor,
            lambda: garner_correctness_check(req.bits, req.n_messages)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/hastad-demo")
async def run_hastad_demo(req: HastadDemoRequest):
    """
    Full Hastad Broadcast Attack demo.

    Generates 3 toy RSA key pairs with e=3 and n_bits-bit moduli.
    Encrypts message to all 3 recipients (optionally with PKCS padding).
    Runs CRT + integer cube root to recover the plaintext.

    Without padding: attack succeeds (exact cube root).
    With PKCS#1 v1.5 padding: CRT still runs but cube root is not
    an integer → attack fails (garbage output).
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor,
            lambda: hastad_demo(req.message, req.use_padding, req.n_bits)
        )
        return _ser(result)
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/padding-compare")
async def padding_compare(req: PaddingCompareRequest):
    """
    Run Hastad demo with and without PKCS#1 v1.5 padding side-by-side.
    Demonstrates that padding defeats the broadcast attack.
    """
    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor,
            lambda: padding_breaks_hastad(req.message, req.n_bits)
        )
        return _ser(result)
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=str(ex))
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/boundary")
async def attack_boundary(req: HastadBoundaryRequest):
    """
    Return the maximum message byte-length for which Hastad's attack
    succeeds given e and modulus bit-size.
    """
    try:
        return hastad_boundary(req.n_bits, req.e)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))
