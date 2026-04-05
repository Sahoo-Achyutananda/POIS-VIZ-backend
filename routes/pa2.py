from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from crypto.prf import aes_prf_direct
from crypto.prf import distinguishing_game
from crypto.prf import ggm_prf_tree
from crypto.prf import prg_from_prf


router = APIRouter()


class PA2PRFRequest(BaseModel):
    key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
    query_bits: str = Field(..., examples=["1011"])
    prf_mode: str = Field(default="ggm-prg", examples=["ggm-prg"])
    foundation: str = Field(default="AES", examples=["AES"])


class PA2PRGFromPRFRequest(BaseModel):
    key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
    depth: int = Field(default=4, ge=1, le=8)
    prf_mode: str = Field(default="ggm-prg", examples=["ggm-prg"])
    foundation: str = Field(default="AES", examples=["AES"])


class PA2DistinguishRequest(BaseModel):
    key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
    depth: int = Field(default=4, ge=1, le=8)
    trials: int = Field(default=100, ge=1, le=1000)
    prf_mode: str = Field(default="ggm-prg", examples=["ggm-prg"])
    foundation: str = Field(default="AES", examples=["AES"])


@router.post("/pa2/prf/evaluate")
def evaluate_pa2_prf(payload: PA2PRFRequest):
    try:
        if payload.prf_mode.lower() == "aes-direct":
            return aes_prf_direct(payload.key_hex, payload.query_bits)
        return ggm_prf_tree(
            key_hex=payload.key_hex,
            query_bits=payload.query_bits,
            prf_mode=payload.prf_mode,
            foundation=payload.foundation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pa2/prg/from-prf")
def evaluate_prg_from_prf(payload: PA2PRGFromPRFRequest):
    try:
        return prg_from_prf(
            key_hex=payload.key_hex,
            depth=payload.depth,
            prf_mode=payload.prf_mode,
            foundation=payload.foundation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pa2/distinguish")
def run_pa2_distinguish(payload: PA2DistinguishRequest):
    try:
        return distinguishing_game(
            key_hex=payload.key_hex,
            depth=payload.depth,
            trials=payload.trials,
            prf_mode=payload.prf_mode,
            foundation=payload.foundation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
