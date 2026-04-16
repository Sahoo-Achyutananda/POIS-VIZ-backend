from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from crypto.pa5_mac import PA5MAC, generate_euf_cma_challenge, SERVER_HIDDEN_KEY_HEX, EUF_CMA_HISTORY

router = APIRouter(prefix="/api/pa5", tags=["pa5"])

class MacRequest(BaseModel):
    mode: str  # "prf", "cbc", "naive", "hmac"
    key_hex: str
    message_hex: str

class VrfyRequest(BaseModel):
    mode: str
    key_hex: str
    message_hex: str
    tag_hex: str

class ForgeRequest(BaseModel):
    message_hex: str
    tag_hex: str

class LengthExtensionRequest(BaseModel):
    original_tag_hex: str
    original_payload_length: int
    suffix_hex: str

class LengthExtensionVerifyRequest(BaseModel):
    key_hex: str
    full_message_hex: str
    forged_tag_hex: str

@router.post("/mac")
def mac_route(req: MacRequest):
    if req.mode == "prf":
        tag = PA5MAC.prf_mac(req.key_hex, req.message_hex)
    elif req.mode == "cbc":
        tag = PA5MAC.cbc_mac(req.key_hex, req.message_hex)
    elif req.mode == "naive":
        tag = PA5MAC.naive_hash_mac(req.key_hex, req.message_hex)
    elif req.mode == "hmac":
        try:
            PA5MAC.hmac(req.key_hex, req.message_hex)
        except NotImplementedError as e:
            return {"error": str(e), "tag_hex": None}
    else:
        return {"error": "Invalid mode", "tag_hex": None}
    
    return {"tag_hex": tag}

@router.post("/vrfy")
def vrfy_route(req: VrfyRequest):
    if req.mode == "prf":
        valid = PA5MAC.prf_vrfy(req.key_hex, req.message_hex, req.tag_hex)
    elif req.mode == "cbc":
        valid = PA5MAC.cbc_vrfy(req.key_hex, req.message_hex, req.tag_hex)
    else:
        return {"error": "Invalid mode", "valid": False}
    return {"valid": valid}

@router.get("/euf-cma/challenge")
def euf_cma_challenge():
    if not EUF_CMA_HISTORY:
        generate_euf_cma_challenge(50)
    return {"challenge_list": EUF_CMA_HISTORY}

@router.post("/euf-cma/forge")
def euf_cma_forge(req: ForgeRequest):
    # Check if message is distinctly NEW (not in history)
    existing_messages = {item["message_hex"].lower() for item in EUF_CMA_HISTORY}
    
    is_new = req.message_hex.lower() not in existing_messages
    valid_crypto = PA5MAC.cbc_vrfy(SERVER_HIDDEN_KEY_HEX, req.message_hex, req.tag_hex)
    success = is_new and valid_crypto

    return {
        "success": success,
        "is_new": is_new,
        "valid_crypto": valid_crypto
    }

@router.post("/length-extension")
def length_extension_route(req: LengthExtensionRequest):
    extended_tag = PA5MAC.length_extend_tag(
        req.original_tag_hex, 
        req.original_payload_length, 
        req.suffix_hex
    )
    return {"extended_tag_hex": extended_tag}

@router.get("/length-extension/pad")
def length_extension_pad(original_payload_length: int):
    padding = PA5MAC.get_padding(original_payload_length)
    return {"padding_hex": padding}

@router.post("/length-extension/verify")
def length_extension_verify(req: LengthExtensionVerifyRequest):
    success = PA5MAC.naive_vrfy(req.key_hex, req.full_message_hex, req.forged_tag_hex)
    return {"success": success}
