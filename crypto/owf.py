import hashlib

from crypto.aes import davies_meyer_owf
from crypto.dlp import dlp_owf
from crypto.utils import normalize_hex


def owf_aes(x: str) -> str:
    """Apply AES-based OWF using input hex as the 128-bit key material."""
    # 16 bytes = 32 hex chars
    key_hex = normalize_hex(x, length=32)
    key = bytes.fromhex(key_hex)
    output = davies_meyer_owf(key)
    return output.hex()


def owf_dlp(x: str) -> str:
    """Apply DLP-based OWF and return result as hex (without 0x)."""
    clean = x.lower().replace("0x", "")
    if clean == "":
        clean = "0"
    x_int = int(clean, 16)
    output = dlp_owf(x_int)
    return format(output, "x")


def get_owf(x: str, foundation: str) -> str:
    """Dispatch OWF based on selected foundation."""
    normalized = foundation.upper()
    if normalized == "AES":
        return owf_aes(x)
    if normalized == "DLP":
        return owf_dlp(x)
    raise ValueError("Invalid foundation. Use 'AES' or 'DLP'.")


def evaluate(x: str, foundation: str) -> str:
    """User-facing evaluate(x) helper requested in PA sheet."""
    return get_owf(x, foundation)


def verify_hardness(x: str, foundation: str, attempts: int = 64) -> dict:
    """Toy hardness demo: try random inversion guesses and report if they fail.

    This function is deterministic for the same inputs.
    """
    target = evaluate(x, foundation)
    foundation_norm = foundation.upper()
    clean_x = x.lower().replace("0x", "") or "0"

    success = False
    recovered = None

    for i in range(attempts):
        if foundation_norm == "AES":
            # 128-bit key candidate (32 hex chars)
            guess = hashlib.sha256(f"aes:{i}".encode("utf-8")).hexdigest()[:32]
        elif foundation_norm == "DLP":
            # Match input width for stable demo behavior
            guess = hashlib.sha256(f"dlp:{i}".encode("utf-8")).hexdigest()[: len(clean_x)]
            if guess == "":
                guess = "0"
        else:
            raise ValueError("Invalid foundation. Use 'AES' or 'DLP'.")

        if evaluate(guess, foundation_norm) == target:
            success = True
            recovered = guess
            break

    return {
        "input": clean_x,
        "foundation": foundation_norm,
        "target_output": target,
        "attempts": attempts,
        "inversion_succeeded": success,
        "recovered_preimage": recovered,
        "note": "Educational demo: random guessing should usually fail.",
    }