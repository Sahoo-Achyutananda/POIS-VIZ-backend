from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from crypto.PA8.dlp_hash import dlp_hash_trace, birthday_attack_hunt

router = APIRouter(prefix="/pa8", tags=["PA8"])

class HashRequest(BaseModel):
    message: str
    use_toy: bool = False

@router.post("/compute")
async def compute_dlp_hash(req: HashRequest):
    try:
        return dlp_hash_trace(req.message, req.use_toy)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/collision-hunt")
async def collision_hunt():
    try:
        # This might take a second or two
        return birthday_attack_hunt(target_bits=16)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
