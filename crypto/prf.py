import hashlib
import random
from dataclasses import dataclass
from typing import Any

from crypto.aes_core import aes_encrypt_block_128
from crypto.prg import hill_prg


MAX_DEPTH = 8


@dataclass
class NodeValue:
    bits: str

    @property
    def hex(self) -> str:
        return bits_to_hex(self.bits)


def clean_hex(value: str) -> str:
    cleaned = (value or "").lower().replace("0x", "")
    if cleaned == "":
        raise ValueError("key must be a non-empty hex string")
    if any(ch not in "0123456789abcdef" for ch in cleaned):
        raise ValueError("key must be valid hexadecimal")
    return cleaned


def clean_query_bits(query_bits: str, max_depth: int = MAX_DEPTH) -> str:
    bits = (query_bits or "").strip()
    if bits == "":
        raise ValueError("query_bits must be non-empty")
    if any(bit not in "01" for bit in bits):
        raise ValueError("query_bits must contain only 0 and 1")
    if len(bits) > max_depth:
        raise ValueError(f"query_bits length must be <= {max_depth}")
    return bits


def bits_to_hex(bits: str) -> str:
    if bits == "":
        return "0"
    padded_len = ((len(bits) + 3) // 4) * 4
    padded = bits.rjust(padded_len, "0")
    return f"{int(padded, 2):0{padded_len // 4}x}"


def hex_to_bits(value: str, target_bits: int | None = None) -> str:
    cleaned = clean_hex(value)
    bits = bin(int(cleaned, 16))[2:].zfill(len(cleaned) * 4)
    if target_bits is None:
        return bits
    if target_bits <= 0:
        return ""
    if len(bits) < target_bits:
        return bits.rjust(target_bits, "0")
    return bits[-target_bits:]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def aes_block_encrypt(key_hex: str, block: bytes) -> bytes:
    key = bytes.fromhex(clean_hex(key_hex).zfill(32)[-32:])
    return aes_encrypt_block_128(key, block)


def aes_prf_direct(key_hex: str, query_bits: str) -> dict[str, Any]:
    bits = clean_query_bits(query_bits)
    query_bytes = int(bits, 2).to_bytes(16, byteorder="big", signed=False)
    output = aes_block_encrypt(key_hex, query_bytes)
    output_hex = output.hex()
    output_bits = bin(int(output_hex, 16))[2:].zfill(128)
    return {
        "mode": "aes-direct",
        "query_bits": bits,
        "input_hex": query_bytes.hex(),
        "output_hex": output_hex,
        "output_bits": output_bits,
    }


def prg_expand_bits(state_bits: str, foundation: str) -> tuple[str, str]:
    if state_bits == "":
        state_bits = "0"
    n = len(state_bits)
    state_hex = bits_to_hex(state_bits)
    expanded = hill_prg(seed=state_hex, length=2 * n, foundation=foundation)["output"]
    left = expanded[:n]
    right = expanded[n : 2 * n]
    return left, right


def aes_expand_bits(root_key_hex: str, state_bits: str) -> tuple[str, str]:
    state_bytes = int(state_bits or "0", 2).to_bytes(16, byteorder="big", signed=False)
    left_block = aes_block_encrypt(root_key_hex, xor_bytes(state_bytes, b"\x00" * 16))
    right_block = aes_block_encrypt(root_key_hex, xor_bytes(state_bytes, b"\xff" * 16))
    left_bits = bin(int(left_block.hex(), 16))[2:].zfill(128)
    right_bits = bin(int(right_block.hex(), 16))[2:].zfill(128)
    return left_bits, right_bits


def ggm_prf_tree(
    key_hex: str,
    query_bits: str,
    prf_mode: str = "ggm-prg",
    foundation: str = "AES",
) -> dict[str, Any]:
    bits = clean_query_bits(query_bits)
    mode = prf_mode.lower()
    foundation_norm = foundation.upper()

    if foundation_norm not in {"AES", "DLP"}:
        raise ValueError("foundation must be AES or DLP")
    if mode not in {"ggm-prg", "ggm-aes"}:
        raise ValueError("prf_mode must be ggm-prg or ggm-aes")

    clean_key = clean_hex(key_hex)
    if mode == "ggm-prg":
        root_bits = hex_to_bits(clean_key)
        state_width = len(root_bits)
    else:
        # AES mode uses a fixed-width 128-bit state.
        root_bits = hex_to_bits(clean_key, 128)
        state_width = 128

    nodes: list[dict[str, Any]] = []
    active_prefixes = {""}
    levels: list[list[str]] = [[root_bits]]

    for level in range(len(bits) + 1):
        current_level_states = levels[level]
        width = 2**level

        for index in range(width):
            prefix = format(index, f"0{level}b") if level > 0 else ""
            value_bits = current_level_states[index]
            is_active = prefix in active_prefixes
            nodes.append(
                {
                    "id": f"L{level}N{index}",
                    "level": level,
                    "index": index,
                    "prefix": prefix,
                    "active": is_active,
                    "value_hex": bits_to_hex(value_bits),
                    "value_preview": f"{bits_to_hex(value_bits)[:10]}...{bits_to_hex(value_bits)[-10:]}"
                    if len(bits_to_hex(value_bits)) > 24
                    else bits_to_hex(value_bits),
                }
            )

        if level == len(bits):
            continue

        next_states: list[str] = []
        bit = bits[level]
        next_active = set()

        for index, state in enumerate(current_level_states):
            if mode == "ggm-prg":
                left, right = prg_expand_bits(state, foundation_norm)
            else:
                left, right = aes_expand_bits(clean_key, state)

            next_states.extend([left, right])
            prefix = format(index, f"0{level}b") if level > 0 else ""
            if prefix in active_prefixes:
                next_active.add(prefix + bit)

        levels.append(next_states)
        active_prefixes = next_active

    leaf_index = int(bits, 2)
    leaf_bits = levels[len(bits)][leaf_index]
    return {
        "mode": mode,
        "foundation": foundation_norm,
        "query_bits": bits,
        "depth": len(bits),
        "state_width": state_width,
        "leaf": {
            "index": leaf_index,
            "prefix": bits,
            "value_bits": leaf_bits,
            "value_hex": bits_to_hex(leaf_bits),
        },
        "nodes": nodes,
    }


def F(
    key_hex: str,
    x_bits: str,
    prf_mode: str = "ggm-aes",
    foundation: str = "AES",
) -> str:
    """Evaluate F(k, x) and return output bits.

    This wrapper keeps a simple PA-friendly interface for downstream modules
    (PA3/PA4/PA5) while reusing the detailed PA2 PRF implementations.
    """
    mode = prf_mode.lower()
    if mode == "aes-direct":
        return aes_prf_direct(key_hex, x_bits)["output_bits"]
    return ggm_prf_tree(
        key_hex=key_hex,
        query_bits=x_bits,
        prf_mode=prf_mode,
        foundation=foundation,
    )["leaf"]["value_bits"]


def prg_from_prf(
    key_hex: str,
    depth: int,
    prf_mode: str = "ggm-prg",
    foundation: str = "AES",
) -> dict[str, Any]:
    if depth < 1 or depth > MAX_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_DEPTH}")

    zero_query = "0" * depth
    one_query = "1" * depth

    if prf_mode.lower() == "aes-direct":
        left = aes_prf_direct(key_hex, zero_query)
        right = aes_prf_direct(key_hex, one_query)
        left_bits = left["output_bits"]
        right_bits = right["output_bits"]
    else:
        left = ggm_prf_tree(key_hex, zero_query, prf_mode=prf_mode, foundation=foundation)
        right = ggm_prf_tree(key_hex, one_query, prf_mode=prf_mode, foundation=foundation)
        left_bits = left["leaf"]["value_bits"]
        right_bits = right["leaf"]["value_bits"]

    combined_bits = left_bits + right_bits
    return {
        "construction": "G(s) = F_s(0^n) || F_s(1^n)",
        "mode": prf_mode,
        "foundation": foundation.upper(),
        "depth": depth,
        "left_query": zero_query,
        "right_query": one_query,
        "left_output_bits": left_bits,
        "right_output_bits": right_bits,
        "output_bits": combined_bits,
        "output_hex": bits_to_hex(combined_bits),
        "output_length": len(combined_bits),
    }


def distinguishing_game(
    key_hex: str,
    depth: int,
    trials: int,
    prf_mode: str = "ggm-prg",
    foundation: str = "AES",
) -> dict[str, Any]:
    if depth < 1 or depth > MAX_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_DEPTH}")
    if trials < 1 or trials > 1000:
        raise ValueError("trials must be between 1 and 1000")

    seed_material = f"{clean_hex(key_hex)}:{depth}:{trials}:{prf_mode}:{foundation.upper()}"
    rng = random.Random(int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest(), 16))

    queries = [format(rng.randrange(2**depth), f"0{depth}b") for _ in range(trials)]
    random_function_table: dict[str, str] = {}

    prf_outputs: list[str] = []
    random_outputs: list[str] = []

    for query in queries:
        if prf_mode.lower() == "aes-direct":
            prf_out = aes_prf_direct(key_hex, query)["output_bits"]
        else:
            prf_out = ggm_prf_tree(key_hex, query, prf_mode=prf_mode, foundation=foundation)["leaf"]["value_bits"]
        prf_outputs.append(prf_out)

        if query not in random_function_table:
            random_function_table[query] = "".join(rng.choice("01") for _ in range(len(prf_out)))
        random_outputs.append(random_function_table[query])

    prf_bits_joined = "".join(prf_outputs)
    rnd_bits_joined = "".join(random_outputs)

    def ones_ratio(bits: str) -> float:
        if bits == "":
            return 0.0
        return bits.count("1") / len(bits)

    prf_ratio = ones_ratio(prf_bits_joined)
    rnd_ratio = ones_ratio(rnd_bits_joined)
    ratio_gap = abs(prf_ratio - rnd_ratio)

    return {
        "mode": prf_mode,
        "foundation": foundation.upper(),
        "depth": depth,
        "trials": trials,
        "metrics": {
            "prf_ones_ratio": prf_ratio,
            "random_ones_ratio": rnd_ratio,
            "ratio_gap": ratio_gap,
            "prf_unique_outputs": len(set(prf_outputs)),
            "random_unique_outputs": len(set(random_outputs)),
        },
        "supports_indistinguishability": ratio_gap < 0.05,
        "sample": [
            {
                "query": q,
                "prf": p[:32] + ("..." if len(p) > 32 else ""),
                "random": r[:32] + ("..." if len(r) > 32 else ""),
            }
            for q, p, r in list(zip(queries, prf_outputs, random_outputs))[:10]
        ],
    }
