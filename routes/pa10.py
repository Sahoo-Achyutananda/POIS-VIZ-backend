import secrets
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from crypto.pa10_hmac import (
    hmac_sha256_trace,
    hmac_verify,
    naive_mac,
    length_extend_attack,
    hmac_extend_attempt,
    eth_enc,
    eth_dec,
)

router = APIRouter(prefix="/pa10", tags=["PA10"])

# ── Per-session hidden key (reset on server restart) ──────────────────────────
_SESSION_KEY = secrets.token_hex(16)


# ── Request models ─────────────────────────────────────────────────────────────

class HMACRequest(BaseModel):
    key_hex: Optional[str] = None  # if None, use session key
    message: str


class VerifyRequest(BaseModel):
    key_hex: Optional[str] = None
    message: str
    tag_hex: str


class LengthExtendRequest(BaseModel):
    message: str       # original message (plaintext)
    suffix: str        # suffix to forge


class EtHEncRequest(BaseModel):
    kE_hex: Optional[str] = None
    kM_hex: Optional[str] = None
    plaintext: str


class EtHDecRequest(BaseModel):
    kE_hex: str
    kM_hex: str
    r_hex: str
    ciphertext_hex: str
    tag_hex: str
    tamper_byte: Optional[int] = None  # index to flip for CCA demo


# ── Helpers ────────────────────────────────────────────────────────────────────

def _resolve_key(key_hex: Optional[str]) -> str:
    return key_hex if key_hex else _SESSION_KEY


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/hmac-compute")
async def compute_hmac(req: HMACRequest):
    """Full HMAC construction trace for the visualiser."""
    try:
        key_hex = _resolve_key(req.key_hex)
        message_hex = req.message.encode().hex()
        trace = hmac_sha256_trace(key_hex, message_hex)
        return {
            **trace,
            "message_text": req.message,
            "message_hex": message_hex,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hmac-verify")
async def verify_hmac(req: VerifyRequest):
    try:
        key_hex = _resolve_key(req.key_hex)
        message_hex = req.message.encode().hex()
        valid = hmac_verify(key_hex, message_hex, req.tag_hex)
        return {"valid": valid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/naive-mac")
async def compute_naive_mac(req: HMACRequest):
    """Compute the broken naive MAC: t = H(k || m)."""
    try:
        key_hex = _resolve_key(req.key_hex)
        message_hex = req.message.encode().hex()
        result = naive_mac(key_hex, message_hex)
        return {
            **result,
            "message_text": req.message,
            "message_hex": message_hex,
            "key_hex": key_hex,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/length-extend")
async def perform_length_extension(req: LengthExtendRequest):
    """
    Perform length extension on H(k||m).
    The frontend sends original (m, t) and a chosen suffix m'.
    The server demonstrates forgery WITHOUT knowing k.
    """
    try:
        # Compute the original MAC with the hidden key (simulating the oracle)
        key_hex = _SESSION_KEY
        message_hex = req.message.encode().hex()
        original = naive_mac(key_hex, message_hex)
        
        suffix_hex = req.suffix.encode().hex()
        
        # Attack — forges without k
        forged = length_extend_attack(
            original["tag_hex"],
            original["payload_len"],
            suffix_hex,
        )

        # Also verify the forged tag actually passes H(k||m_full)
        # m_full = m || padding || suffix
        import struct
        from crypto.sha256_pure import generate_padding
        key_bytes = bytes.fromhex(key_hex)
        msg_bytes = req.message.encode()
        padding = generate_padding(len(key_bytes) + len(msg_bytes))
        suffix_bytes = req.suffix.encode()
        full_msg_bytes = msg_bytes + padding + suffix_bytes
        full_msg_hex = full_msg_bytes.hex()

        # Verify the forged tag independently
        from crypto.pa10_hmac import naive_mac as nm
        verification = nm(key_hex, full_msg_hex)
        tags_match = verification["tag_hex"].lower() == forged["forged_tag_hex"].lower()

        return {
            "original_message": req.message,
            "original_tag_hex": original["tag_hex"],
            "payload_len": original["payload_len"],
            "suffix": req.suffix,
            "suffix_hex": suffix_hex,
            "padding_hex": forged["padding_hex"],
            "forged_tag_hex": forged["forged_tag_hex"],
            "verified": tags_match,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/hmac-resist")
async def demonstrate_hmac_resistance(req: LengthExtendRequest):
    """
    Show HMAC resisting the same length-extension attempt.
    Returns failure details for pedagogy.
    """
    try:
        key_hex = _SESSION_KEY
        message_hex = req.message.encode().hex()
        
        # Compute real HMAC tag
        real_tag = hmac_sha256_trace(key_hex, message_hex)["tag_hex"]
        
        # Attacker tries to extend — always fails
        result = hmac_extend_attempt(key_hex, message_hex, real_tag, req.suffix.encode().hex())
        return {
            "original_message": req.message,
            "original_tag_hex": real_tag,
            "suffix": req.suffix,
            **result,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/eth-enc")
async def encrypt_then_hmac(req: EtHEncRequest):
    try:
        kE = req.kE_hex or secrets.token_hex(16)
        kM = req.kM_hex or secrets.token_hex(16)
        result = eth_enc(kE, kM, req.plaintext)
        return {**result, "kE_hex": kE, "kM_hex": kM, "plaintext": req.plaintext}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/eth-dec")
async def decrypt_then_verify(req: EtHDecRequest):
    try:
        ciphertext_hex = req.ciphertext_hex
        # Optional: tamper a byte for the CCA demo
        if req.tamper_byte is not None:
            c_list = list(bytes.fromhex(ciphertext_hex))
            if 0 <= req.tamper_byte < len(c_list):
                c_list[req.tamper_byte] ^= 0xFF
            ciphertext_hex = bytes(c_list).hex()

        result = eth_dec(req.kE_hex, req.kM_hex, req.r_hex, ciphertext_hex, req.tag_hex)
        return {**result, "tampered": req.tamper_byte is not None}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
