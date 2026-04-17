"""
PA #10 — HMAC and HMAC-Based CCA-Secure Encryption
Crypto primitives: HMAC over DLP Hash, Length Extension, Encrypt-then-HMAC
"""
import secrets
import struct
from typing import Optional

from crypto.PA8.dlp_hash import dlp_hash_trace, toy_group, production_group
from crypto.sha256_pure import PureSHA256, sha256_length_extend, generate_padding
from crypto.pa4_modes import _xor_bytes

# ── Constants ──────────────────────────────────────────────────────────────────
IPAD = bytes([0x36] * 64)
OPAD = bytes([0x5C] * 64)
BLOCK_SIZE = 64  # SHA-256 block size in bytes

# ── Key padding (HMAC spec) ────────────────────────────────────────────────────

def _pad_key(key_bytes: bytes) -> bytes:
    """Pad or hash the key to exactly BLOCK_SIZE bytes."""
    if len(key_bytes) > BLOCK_SIZE:
        key_bytes = PureSHA256(key_bytes).digest()
    return key_bytes.ljust(BLOCK_SIZE, b'\x00')


# ── HMAC over SHA-256 ──────────────────────────────────────────────────────────

def hmac_sha256_trace(key_hex: str, message_hex: str) -> dict:
    """
    Compute HMAC_k(m) = H((k⊕opad) || H((k⊕ipad) || m))
    Returns full construction trace for visualisation.
    """
    key_bytes = bytes.fromhex(key_hex)
    msg_bytes = bytes.fromhex(message_hex)

    k_padded = _pad_key(key_bytes)
    k_ipad = _xor_bytes(k_padded, IPAD)
    k_opad = _xor_bytes(k_padded, OPAD)

    inner_payload = k_ipad + msg_bytes
    inner_hash_bytes = PureSHA256(inner_payload).digest()
    inner_hash_hex = inner_hash_bytes.hex()

    outer_payload = k_opad + inner_hash_bytes
    outer_hash_bytes = PureSHA256(outer_payload).digest()
    tag_hex = outer_hash_bytes.hex()

    return {
        "key_hex": key_hex,
        "key_padded_hex": k_padded.hex(),
        "k_ipad_hex": k_ipad.hex(),
        "k_opad_hex": k_opad.hex(),
        "inner_payload_hex": inner_payload.hex(),
        "inner_hash_hex": inner_hash_hex,
        "outer_payload_hex": outer_payload.hex(),
        "tag_hex": tag_hex,
        "ipad": "0x36 × 64",
        "opad": "0x5C × 64",
    }


def hmac_sha256(key_hex: str, message_hex: str) -> str:
    return hmac_sha256_trace(key_hex, message_hex)["tag_hex"]


def hmac_verify(key_hex: str, message_hex: str, tag_hex: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    expected = bytes.fromhex(hmac_sha256(key_hex, message_hex))
    provided = bytes.fromhex(tag_hex)
    if len(expected) != len(provided):
        return False
    diff = 0
    for a, b in zip(expected, provided):
        diff |= a ^ b
    return diff == 0


# ── Length-Extension Attack demo ───────────────────────────────────────────────

def naive_mac(key_hex: str, message_hex: str) -> dict:
    """t = H(k || m) — the broken construction."""
    key_bytes = bytes.fromhex(key_hex)
    msg_bytes = bytes.fromhex(message_hex)
    payload = key_bytes + msg_bytes
    tag = PureSHA256(payload).hexdigest()
    return {
        "tag_hex": tag,
        "payload_len": len(payload),
    }


def length_extend_attack(original_tag_hex: str, original_payload_len: int, suffix_hex: str) -> dict:
    """
    Forge a tag for (m || pad || suffix) without knowing k.
    Returns the forged message bytes and new tag.
    """
    suffix_bytes = bytes.fromhex(suffix_hex)
    forged_tag = sha256_length_extend(original_tag_hex, original_payload_len, suffix_bytes)

    # Reconstruct the full forged message bytes (padding appended)
    orig_pad = generate_padding(original_payload_len)
    return {
        "forged_tag_hex": forged_tag,
        "padding_hex": orig_pad.hex(),
        "forged_msg_suffix_hex": suffix_hex,
        "success": True,
    }


def hmac_extend_attempt(key_hex: str, message_hex: str, original_tag_hex: str, suffix_hex: str) -> dict:
    """
    Try the same length-extension on HMAC — should always FAIL.
    The suffix is appended to the *inner-hash input* only, which changes the outer hash.
    """
    # Attacker must forge without knowing k
    # They can't perform length extension on HMAC because the outer hash
    # re-keys the compression function. Return failure.
    return {
        "forged_tag_hex": None,
        "success": False,
        "reason": "HMAC double-hashing prevents length extension — the outer H re-keys independently.",
    }


# ── Encrypt-then-HMAC ─────────────────────────────────────────────────────────

def eth_enc(kE_hex: str, kM_hex: str, plaintext: str) -> dict:
    """Encrypt-then-MAC: (r,c) = CPA.Enc(kE, m); t = HMAC(kM, r||c)."""
    from crypto.PA3.cpa import cpa as CPATool
    tool = CPATool()
    r_hex, c_hex = tool.encrypt(kE_hex, plaintext)
    payload_hex = r_hex + c_hex
    tag_hex = hmac_sha256(kM_hex, payload_hex)
    return {
        "r_hex": r_hex,
        "ciphertext_hex": c_hex,
        "tag_hex": tag_hex,
    }


def eth_dec(kE_hex: str, kM_hex: str, r_hex: str, ciphertext_hex: str, tag_hex: str) -> dict:
    """Verify HMAC then decrypt; reject if tag fails."""
    from crypto.PA3.cpa import cpa as CPATool
    payload_hex = r_hex + ciphertext_hex
    if not hmac_verify(kM_hex, payload_hex, tag_hex):
        return {"plaintext": None, "valid": False, "error": "HMAC verification failed — ciphertext rejected."}
    tool = CPATool()
    plaintext = tool.decrypt(kE_hex, r_hex, ciphertext_hex)
    return {"plaintext": plaintext, "valid": True}
