from math import ceil

from crypto.aes_core import aes_decrypt_block_128
from crypto.aes_core import aes_encrypt_block_128

BLOCK_SIZE = 16
MAX_BLOCKS = 5
MAX_MESSAGE_BYTES = 64


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    if pad_len == 0:
        pad_len = BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("invalid padded data length")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("invalid padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("invalid padding bytes")
    return data[:-pad_len]


def _chunk_bytes(data: bytes, chunk_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def _chunk_hex(data: bytes, chunk_size: int = BLOCK_SIZE) -> list[str]:
    return [block.hex() for block in _chunk_bytes(data, chunk_size)]


def _validate_key_iv(key_hex: str, iv_hex: str) -> tuple[bytes, bytes]:
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    if len(key) != BLOCK_SIZE:
        raise ValueError("key must be 16 bytes (32 hex chars)")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV/nonce must be 16 bytes (32 hex chars)")
    return key, iv


def _validate_message_length(message: bytes) -> None:
    if len(message) == 0:
        raise ValueError("message must not be empty")
    if len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("message exceeds max length: 64 bytes")


def _validate_ciphertext_length(ciphertext: bytes) -> None:
    if len(ciphertext) == 0:
        raise ValueError("ciphertext must not be empty")
    if ceil(len(ciphertext) / BLOCK_SIZE) > MAX_BLOCKS:
        raise ValueError("ciphertext exceeds max length: 5 AES blocks (80 bytes)")


class PA4Modes:
    def __init__(self):
        self.block_size = BLOCK_SIZE
        self.max_blocks = MAX_BLOCKS

    def encrypt(self, mode: str, key_hex: str, iv_hex: str, message: str) -> dict:
        mode_l = mode.lower()
        if mode_l not in {"cbc", "ofb", "ctr"}:
            raise ValueError("mode must be one of: cbc, ofb, ctr")

        key, iv = _validate_key_iv(key_hex, iv_hex)
        plaintext = message.encode("utf-8")
        _validate_message_length(plaintext)

        if mode_l == "cbc":
            return self._encrypt_cbc(key, iv, plaintext)
        if mode_l == "ofb":
            return self._encrypt_ofb(key, iv, plaintext)
        return self._encrypt_ctr(key, iv, plaintext)

    def decrypt(self, mode: str, key_hex: str, iv_hex: str, ciphertext_hex: str) -> dict:
        mode_l = mode.lower()
        if mode_l not in {"cbc", "ofb", "ctr"}:
            raise ValueError("mode must be one of: cbc, ofb, ctr")

        key, iv = _validate_key_iv(key_hex, iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        _validate_ciphertext_length(ciphertext)

        if mode_l == "cbc":
            return self._decrypt_cbc(key, iv, ciphertext)
        if mode_l == "ofb":
            return self._decrypt_ofb(key, iv, ciphertext)
        return self._decrypt_ctr(key, iv, ciphertext)

    def flip_demo(
        self,
        mode: str,
        key_hex: str,
        iv_hex: str,
        message: str,
        flip_on: str,
        block_index: int,
        bit_index: int,
    ) -> dict:
        mode_l = mode.lower()
        flip_target = flip_on.lower()

        if flip_target not in {"plaintext", "ciphertext"}:
            raise ValueError("flip_on must be one of: plaintext, ciphertext")

        key, iv = _validate_key_iv(key_hex, iv_hex)
        baseline_enc = self.encrypt(mode_l, key_hex, iv_hex, message)
        baseline_dec = self.decrypt(mode_l, key_hex, iv_hex, baseline_enc["ciphertext_hex"])

        if flip_target == "plaintext":
            original_plain = message.encode("utf-8")
            mutated_plain = self._flip_bit(original_plain, block_index, bit_index)
            if ceil(len(mutated_plain) / BLOCK_SIZE) > MAX_BLOCKS:
                raise ValueError("mutated plaintext exceeds max length: 5 AES blocks")

            mutated_enc = self._encrypt_bytes(mode_l, key, iv, mutated_plain)
            mutated_dec = self._safe_decrypt(mode_l, key_hex, iv_hex, mutated_enc["ciphertext_hex"])

            return {
                "mode": mode_l,
                "flip_on": flip_target,
                "target_block": block_index,
                "target_bit": bit_index,
                "baseline": {
                    "message": message,
                    "ciphertext_hex": baseline_enc["ciphertext_hex"],
                    "decrypted": baseline_dec["plaintext"],
                },
                "after_flip": {
                    "message": mutated_plain.decode("utf-8", errors="replace"),
                    "message_hex": mutated_plain.hex(),
                    "ciphertext_hex": mutated_enc["ciphertext_hex"],
                    **mutated_dec,
                },
            }

        baseline_cipher = bytes.fromhex(baseline_enc["ciphertext_hex"])
        mutated_cipher = self._flip_bit(baseline_cipher, block_index, bit_index)
        mutated_dec = self._safe_decrypt(mode_l, key_hex, iv_hex, mutated_cipher.hex())

        return {
            "mode": mode_l,
            "flip_on": flip_target,
            "target_block": block_index,
            "target_bit": bit_index,
            "baseline": {
                "message": message,
                "ciphertext_hex": baseline_enc["ciphertext_hex"],
                "decrypted": baseline_dec["plaintext"],
            },
            "after_flip": {
                "ciphertext_hex": mutated_cipher.hex(),
                **mutated_dec,
            },
        }

    def _encrypt_bytes(self, mode: str, key: bytes, iv: bytes, plaintext: bytes) -> dict:
        _validate_message_length(plaintext)
        if mode == "cbc":
            return self._encrypt_cbc(key, iv, plaintext)
        if mode == "ofb":
            return self._encrypt_ofb(key, iv, plaintext)
        return self._encrypt_ctr(key, iv, plaintext)

    def _safe_decrypt(self, mode: str, key_hex: str, iv_hex: str, ciphertext_hex: str) -> dict:
        try:
            dec = self.decrypt(mode, key_hex, iv_hex, ciphertext_hex)
            return {
                "decrypted": dec["plaintext"],
                "decrypted_hex": dec.get("plaintext_hex", ""),
                "decryption_error": None,
            }
        except ValueError as exc:
            return {
                "decrypted": None,
                "decrypted_hex": None,
                "decryption_error": str(exc),
            }

    def _encrypt_cbc(self, key: bytes, iv: bytes, plaintext: bytes) -> dict:
        padded = _pkcs7_pad(plaintext)

        if len(padded) // BLOCK_SIZE > MAX_BLOCKS:
            raise ValueError("CBC padded plaintext exceeds max length: 5 AES blocks")

        p_blocks = _chunk_bytes(padded)
        c_blocks: list[bytes] = []
        steps: list[dict] = []

        prev = iv
        for i, block in enumerate(p_blocks):
            xored = _xor_bytes(block, prev)
            cipher_block = aes_encrypt_block_128(key, xored)
            c_blocks.append(cipher_block)
            steps.append(
                {
                    "block": i,
                    "p_i": block.hex(),
                    "chain_in": prev.hex(),
                    "xor_out": xored.hex(),
                    "c_i": cipher_block.hex(),
                }
            )
            prev = cipher_block

        ciphertext = b"".join(c_blocks)
        return {
            "mode": "cbc",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "plaintext_hex": plaintext.hex(),
            "padded_plaintext_hex": padded.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_blocks": _chunk_hex(padded),
            "ciphertext_blocks": _chunk_hex(ciphertext),
            "steps": steps,
        }

    def _decrypt_cbc(self, key: bytes, iv: bytes, ciphertext: bytes) -> dict:
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("CBC ciphertext length must be a multiple of 16 bytes")

        c_blocks = _chunk_bytes(ciphertext)
        p_blocks: list[bytes] = []
        steps: list[dict] = []

        prev = iv
        for i, block in enumerate(c_blocks):
            dec = aes_decrypt_block_128(key, block)
            plain_block = _xor_bytes(dec, prev)
            p_blocks.append(plain_block)
            steps.append(
                {
                    "block": i,
                    "c_i": block.hex(),
                    "chain_in": prev.hex(),
                    "block_dec": dec.hex(),
                    "p_i": plain_block.hex(),
                }
            )
            prev = block

        padded_plaintext = b"".join(p_blocks)
        plaintext = _pkcs7_unpad(padded_plaintext)

        return {
            "mode": "cbc",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "plaintext_hex": plaintext.hex(),
            "padded_plaintext_hex": padded_plaintext.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_blocks": _chunk_hex(padded_plaintext),
            "ciphertext_blocks": _chunk_hex(ciphertext),
            "steps": steps,
        }

    def _encrypt_ofb(self, key: bytes, iv: bytes, plaintext: bytes) -> dict:
        p_blocks = _chunk_bytes(plaintext)
        c_blocks: list[bytes] = []
        steps: list[dict] = []

        stream = iv
        for i, block in enumerate(p_blocks):
            stream = aes_encrypt_block_128(key, stream)
            keystream = stream[: len(block)]
            cipher_block = _xor_bytes(block, keystream)
            c_blocks.append(cipher_block)
            steps.append(
                {
                    "block": i,
                    "p_i": block.hex(),
                    "stream_block": stream.hex(),
                    "keystream_used": keystream.hex(),
                    "c_i": cipher_block.hex(),
                }
            )

        ciphertext = b"".join(c_blocks)
        return {
            "mode": "ofb",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "plaintext_hex": plaintext.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_blocks": _chunk_hex(plaintext),
            "ciphertext_blocks": _chunk_hex(ciphertext),
            "steps": steps,
        }

    def _decrypt_ofb(self, key: bytes, iv: bytes, ciphertext: bytes) -> dict:
        c_blocks = _chunk_bytes(ciphertext)
        p_blocks: list[bytes] = []
        steps: list[dict] = []

        stream = iv
        for i, block in enumerate(c_blocks):
            stream = aes_encrypt_block_128(key, stream)
            keystream = stream[: len(block)]
            plain_block = _xor_bytes(block, keystream)
            p_blocks.append(plain_block)
            steps.append(
                {
                    "block": i,
                    "c_i": block.hex(),
                    "stream_block": stream.hex(),
                    "keystream_used": keystream.hex(),
                    "p_i": plain_block.hex(),
                }
            )

        plaintext = b"".join(p_blocks)
        return {
            "mode": "ofb",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "plaintext_hex": plaintext.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_blocks": _chunk_hex(plaintext),
            "ciphertext_blocks": _chunk_hex(ciphertext),
            "steps": steps,
        }

    def _encrypt_ctr(self, key: bytes, iv: bytes, plaintext: bytes) -> dict:
        p_blocks = _chunk_bytes(plaintext)
        c_blocks: list[bytes] = []
        steps: list[dict] = []

        counter = int.from_bytes(iv, byteorder="big")
        for i, block in enumerate(p_blocks):
            counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
            stream = aes_encrypt_block_128(key, counter_block)
            keystream = stream[: len(block)]
            cipher_block = _xor_bytes(block, keystream)
            c_blocks.append(cipher_block)
            steps.append(
                {
                    "block": i,
                    "p_i": block.hex(),
                    "counter": counter_block.hex(),
                    "stream_block": stream.hex(),
                    "keystream_used": keystream.hex(),
                    "c_i": cipher_block.hex(),
                }
            )
            counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

        ciphertext = b"".join(c_blocks)
        return {
            "mode": "ctr",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "plaintext_hex": plaintext.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_blocks": _chunk_hex(plaintext),
            "ciphertext_blocks": _chunk_hex(ciphertext),
            "steps": steps,
        }

    def _decrypt_ctr(self, key: bytes, iv: bytes, ciphertext: bytes) -> dict:
        c_blocks = _chunk_bytes(ciphertext)
        p_blocks: list[bytes] = []
        steps: list[dict] = []

        counter = int.from_bytes(iv, byteorder="big")
        for i, block in enumerate(c_blocks):
            counter_block = counter.to_bytes(BLOCK_SIZE, byteorder="big")
            stream = aes_encrypt_block_128(key, counter_block)
            keystream = stream[: len(block)]
            plain_block = _xor_bytes(block, keystream)
            p_blocks.append(plain_block)
            steps.append(
                {
                    "block": i,
                    "c_i": block.hex(),
                    "counter": counter_block.hex(),
                    "stream_block": stream.hex(),
                    "keystream_used": keystream.hex(),
                    "p_i": plain_block.hex(),
                }
            )
            counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

        plaintext = b"".join(p_blocks)
        return {
            "mode": "ctr",
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "plaintext_hex": plaintext.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_blocks": _chunk_hex(plaintext),
            "ciphertext_blocks": _chunk_hex(ciphertext),
            "steps": steps,
        }

    def _flip_bit(self, data: bytes, block_index: int, bit_index: int) -> bytes:
        if block_index < 0:
            raise ValueError("block_index must be >= 0")
        if bit_index < 0 or bit_index >= BLOCK_SIZE * 8:
            raise ValueError("bit_index must be in [0, 127]")

        byte_offset = block_index * BLOCK_SIZE + (bit_index // 8)
        if byte_offset >= len(data):
            raise ValueError("selected bit is outside available data length")

        bit_in_byte = 7 - (bit_index % 8)
        mutable = bytearray(data)
        mutable[byte_offset] ^= 1 << bit_in_byte
        return bytes(mutable)
