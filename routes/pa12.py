"""
PA #12 — Textbook RSA & PKCS#1 v1.5  (FastAPI router)
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Literal

from crypto.pa12_rsa import (
    rsa_keygen,
    rsa_enc, rsa_dec,
    pkcs15_enc, pkcs15_dec,
    padding_oracle,
    determinism_demo,
    bleichenbacher_demo,
    mod_inverse, extended_gcd, gcd,
)

router   = APIRouter(prefix="/pa12", tags=["PA12"])
_executor = ThreadPoolExecutor(max_workers=4)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ser(d):
    """Recursively stringify ints to preserve JS precision."""
    if isinstance(d, dict):
        return {k: _ser(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_ser(i) for i in d]
    if isinstance(d, int) and not isinstance(d, bool):
        return str(d)
    return d


# ── Request models ────────────────────────────────────────────────────────────

class KeygenRequest(BaseModel):
    bits: int = Field(512, ge=64, le=2048,
                      description="Bit-length of RSA modulus N (64–2048). "
                                  "Use 512 for instant demo, 2048 for production-like.")


class EncryptRequest(BaseModel):
    N: str = Field(..., description="RSA modulus (decimal string)")
    e: str = Field(..., description="Public exponent (decimal string)")
    message: str = Field(..., description="Plaintext message (UTF-8 string, ≤ k-11 bytes for PKCS)")
    mode: Literal['textbook', 'pkcs15'] = Field('pkcs15')


class DecryptRequest(BaseModel):
    N: str
    d: str
    ciphertext: str = Field(..., description="Ciphertext integer (decimal string)")
    mode: Literal['textbook', 'pkcs15'] = Field('pkcs15')


class DeterminismRequest(BaseModel):
    N: str
    e: str
    d: str
    message: str = Field("yes", description="Short plaintext to demonstrate determinism")


class BleichenbacherRequest(BaseModel):
    bits: int  = Field(256, ge=64, le=512,
                       description="RSA bit-size for this demo (64–512 for speed)")
    message: str = Field("vote:yes", description="Target plaintext for the oracle attack")


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/keygen")
async def generate_keys(req: KeygenRequest):
    """
    Generate RSA key pair (pk, sk, aux).
    Uses PA#13 Miller-Rabin for prime generation.
    Returns all CRT components (p, q, dp, dq, q_inv) for PA#14.
    All big integers serialised as decimal strings.
    """
    loop = asyncio.get_running_loop()
    try:
        pk, sk, aux = await loop.run_in_executor(
            _executor, lambda: rsa_keygen(req.bits)
        )
        return _ser({
            'pk':  pk,
            'sk':  sk,
            'aux': aux,
        })
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/encrypt")
async def encrypt(req: EncryptRequest):
    """
    Encrypt a UTF-8 message with textbook or PKCS#1 v1.5 RSA.
    Returns ciphertext as a decimal string.
    """
    try:
        N, e = int(req.N), int(req.e)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=f"Bad integer: {ex}")

    pk = {'N': N, 'e': e}
    m_bytes = req.message.encode('utf-8')

    loop = asyncio.get_running_loop()
    try:
        if req.mode == 'textbook':
            m_int = int.from_bytes(m_bytes, 'big')
            c = await loop.run_in_executor(_executor, lambda: rsa_enc(pk, m_int))
        else:
            c = await loop.run_in_executor(_executor, lambda: pkcs15_enc(pk, m_bytes))
        return {'ciphertext': str(c), 'ciphertext_hex': hex(c), 'mode': req.mode}
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/decrypt")
async def decrypt(req: DecryptRequest):
    """
    Decrypt a ciphertext (decimal string) with textbook or PKCS#1 v1.5 RSA.
    Returns plaintext as UTF-8 string.
    """
    try:
        N, d, c = int(req.N), int(req.d), int(req.ciphertext)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=f"Bad integer: {ex}")

    sk = {'N': N, 'd': d}

    loop = asyncio.get_running_loop()
    try:
        if req.mode == 'textbook':
            m_int  = await loop.run_in_executor(_executor, lambda: rsa_dec(sk, c))
            k      = (N.bit_length() + 7) // 8
            m_bytes = m_int.to_bytes(k, 'big').lstrip(b'\x00')
        else:
            m_bytes = await loop.run_in_executor(_executor, lambda: pkcs15_dec(sk, c))
        return {'plaintext': m_bytes.decode('utf-8', errors='replace'), 'mode': req.mode}
    except ValueError as ex:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {ex}")
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/determinism-demo")
async def determinism_attack(req: DeterminismRequest):
    """
    Demonstrate textbook RSA determinism (same plaintext → identical ciphertext)
    vs PKCS#1 v1.5 randomisation (random PS → different ciphertext each time).
    """
    try:
        N, e, d = int(req.N), int(req.e), int(req.d)
    except ValueError as ex:
        raise HTTPException(status_code=422, detail=f"Bad integer: {ex}")

    pk = {'N': N, 'e': e}
    sk = {'N': N, 'd': d}

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(
            _executor, lambda: determinism_demo(pk, sk, req.message)
        )
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=400, detail=str(ex))


@router.post("/bleichenbacher-demo")
async def bleichenbacher_attack(req: BleichenbacherRequest):
    """
    Simplified Bleichenbacher CCA2 oracle attack demonstration.
    Generates fresh RSA keys of `bits` bit size, encrypts `message` with
    PKCS#1 v1.5, then shows how adaptive oracle queries leak information.
    """
    loop = asyncio.get_running_loop()
    try:
        def _run():
            pk, sk, aux = rsa_keygen(req.bits)
            return bleichenbacher_demo(pk, sk, req.message), aux

        result, aux = await loop.run_in_executor(_executor, _run)
        return _ser({**result, 'N': aux['p'] * aux['q'],
                     'bits': req.bits})
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))


@router.post("/full-demo")
async def full_demo(req: KeygenRequest):
    """
    Generate keys + run a textbook enc/dec roundtrip + PKCS roundtrip
    in one call. Useful for validating the full pipeline.
    """
    loop = asyncio.get_running_loop()
    try:
        def _run():
            pk, sk, aux = rsa_keygen(req.bits)
            # Textbook roundtrip
            test_msg = b"hello"
            m_int = int.from_bytes(test_msg, 'big')
            c_tb  = rsa_enc(pk, m_int)
            m_tb  = rsa_dec(sk, c_tb)
            # PKCS roundtrip
            c_pk  = pkcs15_enc(pk, test_msg)
            m_pk  = pkcs15_dec(sk, c_pk)
            return {
                'pk': pk, 'sk': sk, 'aux': aux,
                'textbook_ok':  m_tb == m_int,
                'pkcs15_ok':    m_pk == test_msg,
                'test_message': 'hello',
            }
        result = await loop.run_in_executor(_executor, _run)
        return _ser(result)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=str(ex))
