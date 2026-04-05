from crypto.aes_core import aes_encrypt_block_128


BLOCK_SIZE = 16


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two byte arrays of equal length."""
    return bytes(a ^ b for a, b in zip(left, right))


def davies_meyer_owf(key: bytes) -> bytes:
    """AES-based OWF using Davies-Meyer: f(k) = AES_k(0^128) XOR k."""
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES key must be exactly 16 bytes (128 bits)")

    zero_block = b"\x00" * BLOCK_SIZE
    encrypted = aes_encrypt_block_128(key, zero_block)
    return xor_bytes(encrypted, key)