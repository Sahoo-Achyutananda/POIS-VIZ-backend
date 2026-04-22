from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from crypto.pa4_modes import PA4Modes


router = APIRouter()
pa4_modes = PA4Modes()


class PA4EncryptRequest(BaseModel):
    mode: str = Field(..., examples=["cbc"])
    key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
    iv_hex: str = Field(..., examples=["0102030405060708090a0b0c0d0e0f10"])
    message: str = Field(..., examples=["hello pa4"])


class PA4DecryptRequest(BaseModel):
    mode: str = Field(..., examples=["cbc"])
    key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
    iv_hex: str = Field(..., examples=["0102030405060708090a0b0c0d0e0f10"])
    ciphertext_hex: str = Field(..., examples=["aabbcc"])


class PA4FlipDemoRequest(BaseModel):
    mode: str = Field(..., examples=["cbc"])
    key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
    iv_hex: str = Field(..., examples=["0102030405060708090a0b0c0d0e0f10"])
    message: str = Field(..., examples=["hello pa4"])
    flip_on: str = Field(..., examples=["ciphertext"])
    block_index: int = Field(..., ge=0, le=3)
    bit_index: int = Field(..., ge=0, le=127)


@router.post("/pa4/encrypt")
def pa4_encrypt(payload: PA4EncryptRequest):
    try:
        return pa4_modes.encrypt(
            mode=payload.mode,
            key_hex=payload.key_hex,
            iv_hex=payload.iv_hex,
            message=payload.message,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pa4/decrypt")
def pa4_decrypt(payload: PA4DecryptRequest):
    try:
        return pa4_modes.decrypt(
            mode=payload.mode,
            key_hex=payload.key_hex,
            iv_hex=payload.iv_hex,
            ciphertext_hex=payload.ciphertext_hex,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pa4/flip-demo")
def pa4_flip_demo(payload: PA4FlipDemoRequest):
    try:
        return pa4_modes.flip_demo(
            mode=payload.mode,
            key_hex=payload.key_hex,
            iv_hex=payload.iv_hex,
            message=payload.message,
            flip_on=payload.flip_on,
            block_index=payload.block_index,
            bit_index=payload.bit_index,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
