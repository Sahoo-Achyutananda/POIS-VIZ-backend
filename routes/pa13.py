"""
PA #13 — Miller-Rabin Primality Testing  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional

from crypto.pa13_miller_rabin import (
    miller_rabin_trace,
    miller_rabin,
    gen_prime,
    sanity_check_mr,
    carmichael_demo,
    prime_generation_benchmark,
    is_prime,
    mod_exp,
)

router = APIRouter(prefix="/pa13", tags=["PA13"])

# Shared thread pool for CPU-bound prime generation tasks
_executor = ThreadPoolExecutor(max_workers=4)


# ── Request / Response models ─────────────────────────────────────────────────

class TestRequest(BaseModel):
    n: str = Field(..., description="Integer to test as a string (supports >53-bit integers)")
    k: int = Field(40, ge=1, le=100, description="Number of Miller-Rabin rounds (1–100)")

    @property
    def n_int(self) -> int:
        try:
            v = int(self.n)
        except ValueError:
            raise ValueError("n must be a valid integer string")
        if v < 2:
            raise ValueError("n must be ≥ 2")
        return v


class GenPrimeRequest(BaseModel):
    bits: int = Field(512, ge=8, le=4096, description="Bit-length of prime to generate")
    k: int = Field(40, ge=1, le=100)


class SanityRequest(BaseModel):
    prime: str = Field(..., description="The prime to sanity-check (as decimal string)")
    sanity_rounds: int = Field(100, ge=40, le=200, description="MR rounds for verification (≥ generation k=40)")


class CarmichaelRequest(BaseModel):
    n: int = Field(561, ge=3, description="Carmichael candidate to demonstrate")
    k: int = Field(20, ge=1, le=40)


class BenchmarkRequest(BaseModel):
    bits_list: List[int] = Field(default=[512, 1024, 2048])
    trials: int = Field(3, ge=1, le=5)   # max 5 trials per size (2048-bit is slow)
    k: int = Field(40, ge=1, le=100)


class IsPrimeRequest(BaseModel):
    n: int = Field(..., ge=2)
    k: int = Field(40, ge=1, le=100)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/test")
async def test_primality(req: TestRequest):
    """
    Run Miller-Rabin on n with k rounds.
    n is accepted as a decimal string to support integers beyond JS Number.MAX_SAFE_INTEGER.
    """
    try:
        n = req.n_int
    except ValueError as ve:
        raise HTTPException(status_code=422, detail=str(ve))
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(_executor, lambda: miller_rabin_trace(n, req.k))
        # Serialize big ints to strings so JS doesn’t lose precision
        result["n"] = str(result["n"])
        result["d"] = str(result["d"])
        for r in result.get("rounds", []):
            r["a"] = str(r["a"])
            r["x_init"] = str(r["x_init"])
            r["x_history"] = [str(x) for x in r["x_history"]]
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gen-prime")
async def generate_prime(req: GenPrimeRequest):
    """
    Generate a random probable prime of `bits` bits using Miller-Rabin (k=40 rounds).
    The generated prime is returned as a decimal string to preserve precision in JS.
    Also includes a sanity pass: the prime is verified with 100 additional MR rounds.
    """
    try:
        loop = asyncio.get_running_loop()
        prime, candidates, ms = await loop.run_in_executor(
            _executor, lambda: gen_prime(req.bits, req.k)
        )
        # Sanity check: verify the returned prime passes 100 MR rounds
        sanity_pass = miller_rabin(prime, k=100) == "PROBABLY_PRIME"
        return {
            "bits": req.bits,
            "prime": str(prime),          # string to preserve JS precision
            "prime_hex": hex(prime),
            "candidates_tried": candidates,
            "time_ms": round(ms, 3),
            "sanity_100_rounds": sanity_pass,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sanity-check")
async def run_sanity_check(req: SanityRequest):
    """
    Assignment requirement: verify that the output of gen_prime passes 100 MR rounds.

    Takes the *same* prime that was generated (with k=40) and re-tests it with
    sanity_rounds (default=100) rounds.  The result should always be PROBABLY_PRIME,
    demonstrating the correctness of gen_prime.
    """
    try:
        prime = int(req.prime)
    except ValueError:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(status_code=422, detail="prime must be a valid integer string")
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            _executor, lambda: sanity_check_mr(prime, req.sanity_rounds)
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/carmichael-demo")
async def run_carmichael_demo(req: CarmichaelRequest):
    """
    Demonstrate that n=561 (smallest Carmichael number) passes all Fermat
    witnesses but is rejected by Miller-Rabin.
    """
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            _executor, lambda: carmichael_demo(req.n, req.k)
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/benchmark")
async def run_benchmark(req: BenchmarkRequest):
    """
    Benchmark prime generation for bit sizes in bits_list.
    Returns avg candidates and avg time per size, with theoretical O(ln n).

    For 2048-bit at k=40, each candidate requires ~k modular exponentiations
    on 2048-bit numbers. Expect total wall-time of 1–5 minutes for trials=3.
    The frontend should set a long axios timeout (5 minutes) for this endpoint.
    """
    for b in req.bits_list:
        if b < 8 or b > 4096:
            raise HTTPException(
                status_code=422,
                detail=f"bits_list values must be between 8 and 4096, got {b}"
            )
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            _executor,
            lambda: prime_generation_benchmark(req.bits_list, req.trials, req.k)
        )
        return {"results": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/is-prime")
def check_is_prime(req: IsPrimeRequest):
    """Boolean is_prime interface (used by PA#11, PA#12 etc.)."""
    try:
        result = is_prime(req.n, req.k)
        return {"n": req.n, "is_prime": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/preloaded-examples")
def get_preloaded_examples():
    """Return preloaded example numbers for the UI demo panel."""
    return {
        "examples": [
            {
                "label": "561 — Carmichael (fools Fermat)",
                "n": 561,
                "expected": "COMPOSITE",
                "note": "Passes ALL Fermat witnesses but correctly identified COMPOSITE by MR",
            },
            {
                "label": "7919 — Known Prime",
                "n": 7919,
                "expected": "PROBABLY_PRIME",
                "note": "The 1000th prime number",
            },
            {
                "label": "1000000007 — Large Prime",
                "n": 1000000007,
                "expected": "PROBABLY_PRIME",
                "note": "Common competitive-programming prime",
            },
            {
                "label": "1000000008 — Composite",
                "n": 1000000008,
                "expected": "COMPOSITE",
                "note": "Even number, trivially composite",
            },
            {
                "label": "2^31-1 = 2147483647 — Mersenne Prime",
                "n": 2147483647,
                "expected": "PROBABLY_PRIME",
                "note": "M31 — the 8th Mersenne prime",
            },
            {
                "label": "1729 — Taxicab / Carmichael",
                "n": 1729,
                "expected": "COMPOSITE",
                "note": "3 × 7 × 83 — also a Carmichael number",
            },
        ]
    }
