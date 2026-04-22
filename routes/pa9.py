from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from crypto.pa9_birthday import (
    naive_birthday_attack,
    floyd_birthday_attack,
    run_trials,
    toy_hash,
)
from crypto.pa9_history import naive_birthday_attack_history
import math

router = APIRouter(prefix="/pa9", tags=["PA9"])


class AttackRequest(BaseModel):
    n_bits: int = 12    # 8 | 10 | 12 | 14 | 16
    mode: str = "naive" # "naive" | "floyd"


class TrialsRequest(BaseModel):
    n_bits: int = 12
    num_trials: int = 100


@router.post("/attack")
async def run_attack(req: AttackRequest):
    """
    Run one birthday attack (naive or Floyd) for the given output bit-length.
    """
    valid_bits = {8, 10, 12, 14, 16}
    if req.n_bits not in valid_bits:
        raise HTTPException(status_code=422, detail=f"n_bits must be one of {valid_bits}")

    try:
        if req.mode == "floyd":
            return floyd_birthday_attack(req.n_bits)
        else:
            return naive_birthday_attack(req.n_bits)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/attack-history")
async def run_attack_history(req: AttackRequest):
    """
    Run one birthday attack and return the full step-by-step history.
    """
    valid_bits = {8, 10, 12, 14, 16}
    if req.n_bits not in valid_bits:
        raise HTTPException(status_code=422, detail=f"n_bits must be one of {valid_bits}")

    try:
        # History is only supported for naive mode in the player for now
        return naive_birthday_attack_history(req.n_bits)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/trials")
async def run_trial_batch(req: TrialsRequest):
    """
    Run num_trials independent naive birthday attacks for n_bits.
    Returns iteration counts and statistics for the empirical curve.
    """
    valid_bits = {8, 10, 12, 14, 16}
    if req.n_bits not in valid_bits:
        raise HTTPException(status_code=422, detail=f"n_bits must be one of {valid_bits}")
    if not (10 <= req.num_trials <= 500):
        raise HTTPException(status_code=422, detail="num_trials must be between 10 and 500")

    try:
        return run_trials(req.n_bits, req.num_trials)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/theoretical")
async def get_theoretical(n_bits: int = 12):
    """
    Return theoretical birthday CDF values for P(at least one collision after k queries).
    P(k) = 1 - exp(-k*(k-1) / (2 * 2^n))
    Returns enough points to draw a smooth curve up to 3 * birthday_bound.
    """
    import math
    valid_bits = {8, 10, 12, 14, 16}
    if n_bits not in valid_bits:
        raise HTTPException(status_code=422, detail=f"n_bits must be one of {valid_bits}")

    N = 1 << n_bits          # 2^n
    bound = math.isqrt(N)    # birthday bound ≈ 2^(n/2)
    max_k = min(N, bound * 4)

    # Sample 200 points evenly across the range for a smooth curve
    step = max(1, max_k // 200)
    points = []
    for k in range(0, max_k + step, step):
        p = 1.0 - math.exp(-k * (k - 1) / (2 * N))
        points.append({"k": k, "probability": round(p, 6)})

    return {
        "n_bits": n_bits,
        "birthday_bound": bound,
        "N": N,
        "points": points,
    }
