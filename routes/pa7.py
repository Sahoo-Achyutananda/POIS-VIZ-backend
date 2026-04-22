from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from crypto.PA7.md import chunk_message, compute_chain

router = APIRouter(prefix="/pa7", tags=["PA7"])

class PA7InitRequest(BaseModel):
    message: str
    is_hex: bool = False
    
class PA7RecomputeRequest(BaseModel):
    blocks_hex: list[str]

@router.post("/md/init")
def md_init(req: PA7InitRequest):
    try:
        if req.is_hex:
            message_bytes = bytes.fromhex(req.message)
        else:
            message_bytes = req.message.encode("utf-8")
        
        blocks = chunk_message(message_bytes, block_size=8)
        trace = compute_chain(blocks)
        
        return {
            "blocks_hex": [b.hex() for b in blocks],
            "trace": trace
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid Input: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/md/recompute")
def md_recompute(req: PA7RecomputeRequest):
    try:
        blocks = [bytes.fromhex(b) for b in req.blocks_hex]
        for b in blocks:
            if len(b) != 8:
                raise ValueError("All blocks must be exactly 8 bytes (16 hex characters).")
                
        trace = compute_chain(blocks)
        return {
            "blocks_hex": req.blocks_hex,
            "trace": trace
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Hex decoding error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/md/collisions")
def md_collisions():
    """
    Returns a set of predefined colliding inputs for the XOR compression function.
    """
    return [
        {
            "id": 1,
            "name": "Byte Swap (Simple)",
            "msgA": "0102030400000000", # Half A || Half B
            "msgB": "0000000001020304", # Half B || Half A -> Both XOR to 01020304
            "description": "Swapping the 4-byte halves of an 8-byte block produces the same XOR sum."
        },
        {
            "id": 2,
            "name": "XOR Nullification",
            "msgA": "ffffffff00000000", 
            "msgB": "00000000ffffffff",
            "description": "Any arrangement that maintains the overall XOR sum results in a collision."
        },
        {
            "id": 3,
            "name": "Full Zero vs Symmetrical Pairs",
            "msgA": "0000000000000000",
            "msgB": "aabbccddaabbccdd",
            "description": "Two identical 4-byte halves XOR to 0x00000000, colliding with a null block."
        }
    ]

@router.post("/md/dual-compute")
def md_dual_compute(req: dict):
    """
    Computes traces for two different messages (hex) and returns them.
    Expects { "msgA": "...", "msgB": "..." }
    """
    try:
        bytesA = bytes.fromhex(req.get("msgA", ""))
        bytesB = bytes.fromhex(req.get("msgB", ""))
        
        blocksA = chunk_message(bytesA, block_size=8)
        blocksB = chunk_message(bytesB, block_size=8)
        
        traceA = compute_chain(blocksA)
        traceB = compute_chain(blocksB)
        
        return {
            "chainA": { "blocks_hex": [b.hex() for b in blocksA], "trace": traceA },
            "chainB": { "blocks_hex": [b.hex() for b in blocksB], "trace": traceB }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
