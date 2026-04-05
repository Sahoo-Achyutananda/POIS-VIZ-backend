
import random

from crypto.prf import F


class Helpers:

    @staticmethod
    def add_padding(message: bytes, block_size: int = 16) -> bytes:
        """Apply PKCS#7 style padding so length becomes a block multiple."""
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        pad_len = block_size - (len(message) % block_size)
        if pad_len == 0:
            pad_len = block_size
        return message + bytes([pad_len] * pad_len)

    @staticmethod
    def remove_padding(padded_message: bytes, block_size: int = 16) -> bytes:
        """Remove PKCS#7 padding and validate it for safer decoding."""
        if len(padded_message) == 0:
            raise ValueError("padded message cannot be empty")
        if len(padded_message) % block_size != 0:
            raise ValueError("ciphertext length must be a multiple of block size")

        pad_len = padded_message[-1]
        if pad_len < 1 or pad_len > block_size:
            raise ValueError("invalid padding length")

        expected = bytes([pad_len] * pad_len)
        if padded_message[-pad_len:] != expected:
            raise ValueError("invalid padding bytes")
        return padded_message[:-pad_len]

    @staticmethod
    def xor_bytes(left: bytes, right: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(left, right))

    @staticmethod
    def split_blocks(data: bytes, block_size: int = 16) -> list[bytes]:
        return [data[i : i + block_size] for i in range(0, len(data), block_size)]


class cpa:

    def __init__(self):
        self.block_size = 16
        self.query_bits = 8

    def _counter_to_query_bits(self, r: int, counter: int) -> str:
        # We use the PA2 PRF with depth 8, so each PRF input is 8 bits.
        query_value = (r + counter) % (2**self.query_bits)
        return format(query_value, f"0{self.query_bits}b")

    def _prf_pad_block(self, key_hex: str, r: int, counter: int) -> bytes:
        query_bits = self._counter_to_query_bits(r, counter)
        pad_bits = F(
            key_hex=key_hex,
            x_bits=query_bits,
            prf_mode="ggm-aes",
            foundation="AES",
        )[: self.block_size * 8]
        return int(pad_bits, 2).to_bytes(self.block_size, byteorder="big")

    def encrypt(self, key_hex: str, message: str) -> tuple[str, str]:
        """Enc(k, m) -> (r, c)."""
        if message is None:
            raise ValueError("message must not be None")

        message_bytes = message.encode("utf-8")
        padded = Helpers.add_padding(message_bytes, self.block_size)
        blocks = Helpers.split_blocks(padded, self.block_size)

        r = random.randrange(0, 2**self.query_bits)
        ciphertext_blocks: list[bytes] = []

        for i, block in enumerate(blocks):
            pad_block = self._prf_pad_block(key_hex, r, i)
            ciphertext_blocks.append(Helpers.xor_bytes(block, pad_block))

        ciphertext = b"".join(ciphertext_blocks)
        return f"{r:02x}", ciphertext.hex()

    def decrypt(self, key_hex: str, r_hex: str, ciphertext_hex: str) -> str:
        """Dec(k, r, c) -> m."""
        if r_hex is None or ciphertext_hex is None:
            raise ValueError("r and ciphertext must not be None")

        r = int(r_hex, 16)
        ciphertext = bytes.fromhex(ciphertext_hex)

        if len(ciphertext) % self.block_size != 0:
            raise ValueError("ciphertext length must be a multiple of block size")

        plain_blocks: list[bytes] = []
        blocks = Helpers.split_blocks(ciphertext, self.block_size)

        for i, block in enumerate(blocks):
            pad_block = self._prf_pad_block(key_hex, r, i)
            plain_blocks.append(Helpers.xor_bytes(block, pad_block))

        padded_plaintext = b"".join(plain_blocks)
        plaintext = Helpers.remove_padding(padded_plaintext, self.block_size)
        return plaintext.decode("utf-8")

    def simulate_ind_cpa_game(
        self,
        key_hex: str,
        rounds: int = 20,
        oracle_queries: int = 50,
    ) -> dict:
        """Run a beginner-friendly IND-CPA simulation with a dummy random adversary."""
        if rounds <= 0:
            raise ValueError("rounds must be positive")
        if oracle_queries <= 0:
            raise ValueError("oracle_queries must be positive")

        wins = 0
        transcripts = []

        for round_index in range(rounds):
            # Dummy adversary makes oracle queries but does not learn a useful strategy.
            for i in range(oracle_queries):
                self.encrypt(key_hex, f"query-{round_index}-{i}")

            m0 = f"left-{round_index:03d}-fixed-len"
            m1 = f"rght-{round_index:03d}-fixed-len"
            b = random.randint(0, 1)
            challenge_r, challenge_c = self.encrypt(key_hex, m0 if b == 0 else m1)

            # Random-guess adversary; expected success probability is close to 1/2.
            guess = random.randint(0, 1)
            won = guess == b
            wins += int(won)

            transcripts.append(
                {
                    "round": round_index + 1,
                    "b": b,
                    "guess": guess,
                    "won": won,
                    "challenge_r": challenge_r,
                    "challenge_c_preview": challenge_c[:32] + "...",
                }
            )

        win_rate = wins / rounds
        advantage = abs(win_rate - 0.5)
        return {
            "rounds": rounds,
            "oracle_queries_per_round": oracle_queries,
            "wins": wins,
            "win_rate": win_rate,
            "advantage": advantage,
            "close_to_zero": advantage <= 0.1,
            "transcript_preview": transcripts[:5],
        }

    def encrypt_broken(self, key_hex: str, message: str, reused_r_hex: str = "00") -> tuple[str, str]:
        """Broken variant: deterministic encryption because r is reused."""
        if message is None:
            raise ValueError("message must not be None")

        message_bytes = message.encode("utf-8")
        padded = Helpers.add_padding(message_bytes, self.block_size)
        blocks = Helpers.split_blocks(padded, self.block_size)

        r = int(reused_r_hex, 16)
        ciphertext_blocks: list[bytes] = []

        for i, block in enumerate(blocks):
            pad_block = self._prf_pad_block(key_hex, r, i)
            ciphertext_blocks.append(Helpers.xor_bytes(block, pad_block))

        ciphertext = b"".join(ciphertext_blocks)
        return reused_r_hex.lower(), ciphertext.hex()

    def broken_variant_attack(self, key_hex: str, message: str = "same-message") -> dict:
        """Show why nonce reuse breaks CPA security."""
        r1, c1 = self.encrypt_broken(key_hex, message, reused_r_hex="00")
        r2, c2 = self.encrypt_broken(key_hex, message, reused_r_hex="00")

        detected = (r1 == r2) and (c1 == c2)
        return {
            "message": message,
            "first": {"r": r1, "c": c1},
            "second": {"r": r2, "c": c2},
            "adversary_detected_reuse": detected,
            "broken": detected,
        }