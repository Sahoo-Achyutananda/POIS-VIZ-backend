from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from crypto.pa6_cca import CCASecure, get_cca_challenge, CCA_GAME_SERVER_KEY_E, CCA_GAME_SERVER_KEY_M, CCA_CHALLENGE_CID

router = APIRouter(prefix="/pa6", tags=["PA6"])

class EncryptRequest(BaseModel):
    ke_hex: str
    km_hex: str
    message: str

class DecryptRequest(BaseModel):
    ke_hex: str
    km_hex: str
    r_hex: str
    c_hex: str
    tag_hex: str

class MalleabilityRequest(BaseModel):
    ke_hex: str
    km_hex: str
    message: str
    flip_bit_index: int

class EncryptOracleRequest(BaseModel):
    message: str

import secrets
import uuid
from typing import Any

CCA_GAME_SESSIONS: dict[str, dict[str, Any]] = {}

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

class PA6CCAStartRequest(BaseModel):
    session_id: str | None = None
    m0: str
    m1: str

class PA6CCAOracleRequest(BaseModel):
    session_id: str
    message: str

class PA6CCADecryptRequest(BaseModel):
    session_id: str
    r_hex: str
    c_hex: str
    tag_hex: str

class PA6CCAGuessRequest(BaseModel):
    session_id: str
    guess: int

@router.post("/cca-game/init")
def cca_init():
    session_id = str(uuid.uuid4())
    CCA_GAME_SESSIONS[session_id] = {
        "rounds": 0,
        "wins": 0,
        "pending": None,
        "enc_queries": set(),
        "ke_hex": secrets.token_hex(16),
        "km_hex": secrets.token_hex(16)
    }
    return {
        "session_id": session_id,
        "rounds_played": 0,
        "wins": 0,
        "win_rate": 0,
        "advantage": 0
    }

@router.post("/cca-game/start")
def cca_start(payload: PA6CCAStartRequest):
    if len(payload.m0) != len(payload.m1):
        raise HTTPException(status_code=400, detail="m0 and m1 must be of equal length")
    
    session_id = payload.session_id or str(uuid.uuid4())
    if session_id not in CCA_GAME_SESSIONS:
        CCA_GAME_SESSIONS[session_id] = {
            "rounds": 0,
            "wins": 0,
            "pending": None,
            "ke_hex": secrets.token_hex(16),
            "km_hex": secrets.token_hex(16)
        }
        
    session = CCA_GAME_SESSIONS[session_id]
    b = secrets.randbelow(2)
    round_id = str(uuid.uuid4())
    chosen = payload.m0 if b == 0 else payload.m1
    
    cca = CCASecure()
    challenge = cca.encrypt(session["ke_hex"], session["km_hex"], chosen)
    
    session["pending"] = {
        "round_id": round_id,
        "b": b,
        "challenge": challenge
    }
    
    return {
        "session_id": session_id,
        "round_id": round_id,
        "challenge": challenge,
        **_stats(session)
    }

@router.post("/cca-game/encrypt-oracle")
def cca_encrypt_oracle(req: PA6CCAOracleRequest):
    if req.session_id not in CCA_GAME_SESSIONS:
        raise HTTPException(status_code=404, detail="session not found")
        
    session = CCA_GAME_SESSIONS[req.session_id]
        
    cca = CCASecure()
    res = cca.encrypt(session["ke_hex"], session["km_hex"], req.message)
    session.setdefault("enc_queries", set()).add((res["r_hex"], res["c_hex"], res["tag_hex"]))
    return res

@router.post("/cca-game/decrypt-oracle")
def cca_decrypt_oracle(req: PA6CCADecryptRequest):
    if req.session_id not in CCA_GAME_SESSIONS:
        raise HTTPException(status_code=404, detail="session not found")
        
    session = CCA_GAME_SESSIONS[req.session_id]
    pending = session.get("pending")

    if (req.r_hex, req.c_hex, req.tag_hex) in session.setdefault("enc_queries", set()):
        raise HTTPException(status_code=400, detail="Already tracked during encryption (redundant query)")

    if pending:
        chal = pending["challenge"]
        if req.r_hex == chal["r_hex"] and req.c_hex == chal["c_hex"] and req.tag_hex == chal["tag_hex"]:
            raise HTTPException(status_code=400, detail="Cannot query decryption oracle on the challenge ciphertext!")
        
    cca = CCASecure()
    plaintext = cca.decrypt(session["ke_hex"], session["km_hex"], req.r_hex, req.c_hex, req.tag_hex)
    return {"plaintext": plaintext}

@router.post("/cca-game/guess")
def cca_guess(req: PA6CCAGuessRequest):
    if req.session_id not in CCA_GAME_SESSIONS:
        raise HTTPException(status_code=404, detail="session not found")
        
    session = CCA_GAME_SESSIONS[req.session_id]
    pending = session.get("pending")
    if not pending:
        raise HTTPException(status_code=400, detail="no active challenge")

    b = pending["b"]
    correct = (req.guess == b)

    session["rounds"] += 1
    if correct:
        session["wins"] += 1
    session["pending"] = None

    return {
        "correct": correct,
        "revealed_b": b,
        **_stats(session),
    }
