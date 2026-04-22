G = 5
P = 23


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """Compute base^exponent mod modulus using square-and-multiply."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1
    base = base % modulus
    exp = exponent

    while exp > 0:
        # If current bit of exponent is 1, multiply into result.
        if exp % 2 == 1:
            result = (result * base) % modulus

        # Square base and move to next exponent bit.
        base = (base * base) % modulus
        exp //= 2

    return result


def dlp_owf(x: int, g: int = G, p: int = P) -> int:
    """DLP-style OWF demo: f(x) = g^x mod p."""
    return mod_exp(g, x, p)