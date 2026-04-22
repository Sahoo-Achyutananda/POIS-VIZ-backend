import hashlib
from typing import Dict, List, Tuple

from crypto.owf import get_owf
from crypto.utils import generate_r, hex_to_bin, match_length_bits


def hardcore_bit_goldreich_levin(x_hex: str) -> Tuple[str, str]:
    """Compute Goldreich-Levin hardcore bit.

    hc(x, r) = <x, r> mod 2

    Returns:
    - bit as "0" or "1"
    - r used as a binary string (length matched to x bits)
    """
    x_bits = hex_to_bin(x_hex)
    if x_bits == "":
        x_bits = "0"

    # Deterministic r from SHA-256(x)
    r_hex = generate_r(x_hex)
    r_bits_full = hex_to_bin(r_hex)
    r_bits = match_length_bits(r_bits_full, len(x_bits))

    # Dot product mod 2 over bits: XOR of (x_i AND r_i)
    parity = 0
    for xb, rb in zip(x_bits, r_bits):
        and_bit = int(xb) & int(rb)
        parity ^= and_bit

    return str(parity), r_bits


class PRG:
    """HILL-style PRG built from an OWF and a hardcore bit predicate."""

    def __init__(self, seed: str, foundation: str):
        self.seed = seed.lower().replace("0x", "")
        self.foundation = foundation.upper()
        self.state = self.seed
        self.steps: List[Dict[str, str]] = []

    def next_bits(self, n: int) -> Dict[str, object]:
        """Generate n pseudorandom bits and capture each internal step."""
        if n < 0:
            raise ValueError("length must be non-negative")

        output_bits: List[str] = []
        x_i = self.state

        for i in range(n):
            bit, r_bits = hardcore_bit_goldreich_levin(x_i)
            x_next = get_owf(x_i, self.foundation)

            self.steps.append(
                {
                    "step": i + 1,
                    "input_state": x_i,
                    "r": r_bits,
                    "output_bit": bit,
                    "next_state": x_next,
                }
            )

            output_bits.append(bit)
            x_i = x_next

        self.state = x_i
        return {"output": "".join(output_bits), "steps": self.steps}


def hill_prg(seed: str, length: int, foundation: str) -> Dict[str, object]:
    """Convenience function for API usage."""
    prg = PRG(seed=seed, foundation=foundation)
    return prg.next_bits(length)


def prg_as_owf(seed: str, foundation: str, output_length: int = 128) -> str:
    """Backward-direction demo idea: define F(s) = G(s)."""
    return hill_prg(seed=seed, length=output_length, foundation=foundation)["output"]


def verify_prg_as_owf_hardness(
    seed: str,
    foundation: str,
    output_length: int = 128,
    attempts: int = 64,
) -> Dict[str, object]:
    """Toy inversion demo for F(s)=G(s): random guessing should usually fail.

    This is an educational simulation, not a formal proof.
    """
    target = prg_as_owf(seed=seed, foundation=foundation, output_length=output_length)
    seed_len = max(1, len(seed.lower().replace("0x", "")))

    found = False
    found_seed = None

    for i in range(attempts):
        candidate = hashlib.sha256(f"{foundation}:{i}".encode("utf-8")).hexdigest()[:seed_len]
        candidate_out = prg_as_owf(
            seed=candidate,
            foundation=foundation,
            output_length=output_length,
        )
        if candidate_out == target:
            found = True
            found_seed = candidate
            break

    return {
        "construction": "F(s) = G(s)",
        "target_output": target,
        "attempts": attempts,
        "inversion_found": found,
        "recovered_seed": found_seed,
        "note": "Educational demo: random inversion attempts should usually fail.",
    }
