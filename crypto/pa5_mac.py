import secrets
import hashlib
from crypto.prf import aes_block_encrypt
from crypto.prf import aes_block_encrypt
from crypto.pa4_modes import _xor_bytes, _chunk_bytes
from crypto.sha256_pure import PureSHA256, sha256_length_extend, generate_padding

class PA5MAC:
    @staticmethod
    def _pad_block(data_bytes: bytes) -> bytes:
        if len(data_bytes) >= 16:
            return data_bytes[:16]
        return data_bytes.ljust(16, b'\x00')

    @classmethod
    def prf_mac(cls, key_hex: str, message_hex: str) -> str:
        """
        PRF-MAC (fixed-length): Mac(k, m) = F_k(m).
        Handles messages of exactly one block length n (16 bytes).
        """
        key = key_hex.zfill(32)[-32:]
        m_bytes = bytes.fromhex(message_hex)
        m_pad = cls._pad_block(m_bytes)
        
        # Uses F_k from PA2 (AES directly for 1 block)
        output_bytes = aes_block_encrypt(key, m_pad)
        return output_bytes.hex()

    @classmethod
    def prf_vrfy(cls, key_hex: str, message_hex: str, tag_hex: str) -> bool:
        expected = cls.prf_mac(key_hex, message_hex)
        return expected.lower() == tag_hex.lower()

    @classmethod
    def cbc_mac(cls, key_hex: str, message_hex: str) -> str:
        """
        CBC-MAC (variable-length).
        """
        key = key_hex.zfill(32)[-32:]
        m_bytes = bytes.fromhex(message_hex)
        blocks = _chunk_bytes(m_bytes, 16)
        if not blocks:
            blocks = [b'\x00' * 16]
            
        t = b'\x00' * 16
        for block in blocks:
            # Need to pad the last block if it's less than 16 bytes
            padded = block.ljust(16, b'\x00')
            chain_input = _xor_bytes(t, padded)
            t = aes_block_encrypt(key, chain_input)
            
        return t.hex()

    @classmethod
    def cbc_vrfy(cls, key_hex: str, message_hex: str, tag_hex: str) -> bool:
        expected = cls.cbc_mac(key_hex, message_hex)
        return expected.lower() == tag_hex.lower()

    @classmethod
    def hmac(cls, key_hex: str, message_hex: str) -> str:
        """
        Stub function demonstrating forward pointer to PA10.
        """
        raise NotImplementedError("HMAC full implementation is reserved for PA#10. Do not use library HMAC.")

    @classmethod
    def naive_hash_mac(cls, key_hex: str, message_hex: str) -> str:
        """
        Naive MAC: t = H(k || m). Used for Length Extension demo.
        """
        key_bytes = bytes.fromhex(key_hex)
        message_bytes = bytes.fromhex(message_hex)
        # Using standard SHA256 here, or PureSHA256
        payload = key_bytes + message_bytes
        hasher = PureSHA256(payload)
        return hasher.hexdigest()

    @classmethod
    def get_naive_hash_payload_length(cls, key_hex: str, message_hex: str) -> int:
        return len(bytes.fromhex(key_hex)) + len(bytes.fromhex(message_hex))

    @classmethod
    def length_extend_tag(cls, original_tag_hex: str, original_payload_length: int, suffix_hex: str) -> str:
        suffix_bytes = bytes.fromhex(suffix_hex)
        return sha256_length_extend(original_tag_hex, original_payload_length, suffix_bytes)

    @classmethod
    def get_padding(cls, original_payload_length: int) -> str:
        return generate_padding(original_payload_length).hex()

    @classmethod
    def naive_vrfy(cls, key_hex: str, full_message_hex: str, tag_hex: str) -> bool:
        """Verifies H(k || m) == tag."""
        expected = cls.naive_hash_mac(key_hex, full_message_hex)
        return expected.lower() == tag_hex.lower()

# Global hidden logic for EUF-CMA
SERVER_HIDDEN_KEY_HEX = secrets.token_hex(16)
EUF_CMA_HISTORY = []

def generate_euf_cma_challenge(count=50):
    global EUF_CMA_HISTORY
    EUF_CMA_HISTORY.clear()
    for _ in range(count):
        # random message lengths between 16 and 64 bytes
        mlen = secrets.choice([16, 32, 48, 64])
        m_bytes = secrets.token_bytes(mlen)
        tag = PA5MAC.cbc_mac(SERVER_HIDDEN_KEY_HEX, m_bytes.hex())
        EUF_CMA_HISTORY.append({"message_hex": m_bytes.hex(), "tag_hex": tag})
    return EUF_CMA_HISTORY
