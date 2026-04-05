import secrets
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from crypto.PA3.cpa import cpa


router = APIRouter()
cipher = cpa()


class PA3CPAStartRequest(BaseModel):
    session_id: str | None = None
    m0: str = Field(..., examples=["left-message"])
    m1: str = Field(..., examples=["rght-message"])
    reuse_nonce: bool = Field(default=False)

class PA3CPAGuessRequest(BaseModel):
    session_id: str = Field(...)
    round_id: str = Field(...)
    guess: int = Field(..., ge=0, le=1)


class PA3CPAOracleRequest(BaseModel):
    session_id: str = Field(...)
    round_id: str = Field(...)
    message: str = Field(..., examples=["oracle-query"])

GAME_SESSIONS: dict[str, dict[str, Any]] = {}

def _init_session() -> dict[str, Any]:
    return {
        "rounds": 0,
        "wins": 0,
        "pending": None,
        # Keep one fixed demo key per session so rounds are comparable.
        "key_hex": secrets.token_hex(16),
        "reused_r_hex": "00",
    }

def _stats(session: dict[str, Any]) -> dict[str, Any]:
    rounds = session["rounds"]
    wins = session["wins"]
    win_rate = (wins / rounds) if rounds > 0 else 0.0
    advantage = abs(win_rate - 0.5)
    return {
        "rounds_played": rounds,
        "wins": wins,
        "win_rate": win_rate,
        "advantage": advantage,
    }

@router.post("/pa3/cpa/start")
def pa3_cpa_start(payload: PA3CPAStartRequest):
    try:
        if len(payload.m0) != len(payload.m1):
            raise ValueError("m0 and m1 must be of equal length")

        session_id = payload.session_id or str(uuid.uuid4())
        if session_id not in GAME_SESSIONS:
            GAME_SESSIONS[session_id] = _init_session()

        session = GAME_SESSIONS[session_id]
        b = secrets.randbelow(2)
        round_id = str(uuid.uuid4())
        chosen = payload.m0 if b == 0 else payload.m1

        key_hex = session["key_hex"]
        if payload.reuse_nonce:
            r, c = cipher.encrypt_broken(
                key_hex=key_hex,
                message=chosen,
                reused_r_hex=session["reused_r_hex"],
            )
        else:
            r, c = cipher.encrypt(key_hex=key_hex, message=chosen)

        session["pending"] = {
            "round_id": round_id,
            "b": b,
            "reuse_nonce": payload.reuse_nonce,
        }

        return {
            "session_id": session_id,
            "round_id": round_id,
            "challenge": {"r": r, "c": c},
            **_stats(session),
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pa3/cpa/oracle")
def pa3_cpa_oracle(payload: PA3CPAOracleRequest):
    if payload.session_id not in GAME_SESSIONS:
        raise HTTPException(status_code=404, detail="session not found")

    session = GAME_SESSIONS[payload.session_id]
    pending = session.get("pending")

    if not pending:
        raise HTTPException(status_code=400, detail="no active round")
    if pending["round_id"] != payload.round_id:
        raise HTTPException(status_code=400, detail="round mismatch")

    key_hex = session["key_hex"]
    reuse_nonce = pending.get("reuse_nonce", False)

    try:
        if reuse_nonce:
            r, c = cipher.encrypt_broken(
                key_hex=key_hex,
                message=payload.message,
                reused_r_hex=session["reused_r_hex"],
            )
        else:
            r, c = cipher.encrypt(key_hex=key_hex, message=payload.message)

        return {
            "session_id": payload.session_id,
            "round_id": payload.round_id,
            "oracle": {"r": r, "c": c},
            "reuse_nonce": reuse_nonce,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    
@router.post("/pa3/cpa/guess")
def pa3_cpa_guess(payload: PA3CPAGuessRequest):
    if payload.session_id not in GAME_SESSIONS:
        raise HTTPException(status_code=404, detail="session not found")

    session = GAME_SESSIONS[payload.session_id]
    pending = session.get("pending")

    if not pending:
        raise HTTPException(status_code=400, detail="no active round")
    if pending["round_id"] != payload.round_id:
        raise HTTPException(status_code=400, detail="round mismatch")

    b = pending["b"]
    correct = (payload.guess == b)

    session["rounds"] += 1
    if correct:
        session["wins"] += 1
    session["pending"] = None

    return {
        "correct": correct,
        "revealed_b": b,
        **_stats(session),
    }