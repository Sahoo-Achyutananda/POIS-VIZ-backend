import hashlib


def normalize_hex(x: str, length: int) -> str:
    """Normalize a hex string to a fixed number of hex characters.

    - Removes optional 0x prefix.
    - Keeps lowercase for consistency.
    - Left-pads with zeros if too short.
    - Keeps the rightmost part if too long.
    """
    clean = x.lower().replace("0x", "")
    if len(clean) < length:
        clean = clean.zfill(length)
    elif len(clean) > length:
        clean = clean[-length:]
    return clean


def hex_to_bin(x: str) -> str:
    """Convert a hex string to a binary string (4 bits per hex char)."""
    clean = x.lower().replace("0x", "")
    if clean == "":
        return ""
    return "".join(f"{int(ch, 16):04b}" for ch in clean)


def generate_r(x: str) -> str:
    """Generate deterministic r from SHA-256(x).

    Returns a 64-char hex string (256 bits).
    """
    clean = x.lower().replace("0x", "")
    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()
    return digest


def match_length_bits(source_bits: str, target_length: int) -> str:
    """Repeat/truncate a bit-string so it matches target_length.

    This keeps the process deterministic for any input length.
    """
    if target_length <= 0:
        return ""
    if source_bits == "":
        return "0" * target_length
    repeats = (target_length + len(source_bits) - 1) // len(source_bits)
    expanded = source_bits * repeats
    return expanded[:target_length]
