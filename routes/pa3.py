from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from crypto.PA3.cpa import cpa


router = APIRouter()
cipher = cpa()


class PA3EncryptRequest(BaseModel):
	key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
	message: str = Field(..., examples=["hello world"])


class PA3DecryptRequest(BaseModel):
	key_hex: str = Field(..., examples=["00112233445566778899aabbccddeeff"])
	r: str = Field(..., examples=["1a"])
	c: str = Field(..., examples=["7f3a91c2"])
	strict: bool = True


@router.post("/pa3/encrypt")
def pa3_encrypt(payload: PA3EncryptRequest):
	try:
		r, c = cipher.encrypt(payload.key_hex, payload.message)
		return {"r": r, "c": c}
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/pa3/decrypt")
def pa3_decrypt(payload: PA3DecryptRequest):
	try:
		m = cipher.decrypt(payload.key_hex, payload.r, payload.c, strict_padding=payload.strict)
		return {"m": m}
	except ValueError as exc:
		raise HTTPException(status_code=400, detail=str(exc)) from exc