import math
from collections import Counter
from typing import Dict


def _clean_bits(bits: str) -> str:
    return "".join(ch for ch in bits if ch in {"0", "1"})


def frequency_monobit_test(bits: str, alpha: float = 0.01) -> Dict[str, object]:
    """NIST-style monobit frequency test."""
    data = _clean_bits(bits)
    n = len(data)
    if n == 0:
        raise ValueError("Bitstring must not be empty")

    ones = data.count("1")
    zeros = n - ones
    s_obs = abs(ones - zeros) / math.sqrt(n)
    p_value = math.erfc(s_obs / math.sqrt(2.0))

    return {
        "name": "frequency_monobit",
        "n": n,
        "ones": ones,
        "zeros": zeros,
        "p_value": p_value,
        "pass": p_value >= alpha,
    }


def runs_test(bits: str, alpha: float = 0.01) -> Dict[str, object]:
    """NIST-style runs test."""
    data = _clean_bits(bits)
    n = len(data)
    if n == 0:
        raise ValueError("Bitstring must not be empty")

    ones = data.count("1")
    pi = ones / n

    # Runs test requires proportion not too far from 1/2
    tau = 2.0 / math.sqrt(n)
    if abs(pi - 0.5) >= tau:
        return {
            "name": "runs",
            "n": n,
            "pi": pi,
            "runs": None,
            "p_value": 0.0,
            "pass": False,
            "note": "Failed prerequisite: pi too far from 0.5",
        }

    runs = 1
    for i in range(1, n):
        if data[i] != data[i - 1]:
            runs += 1

    numerator = abs(runs - (2.0 * n * pi * (1.0 - pi)))
    denominator = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    p_value = math.erfc(numerator / denominator)

    return {
        "name": "runs",
        "n": n,
        "pi": pi,
        "runs": runs,
        "p_value": p_value,
        "pass": p_value >= alpha,
    }


def serial_test_m2(bits: str, alpha: float = 0.01) -> Dict[str, object]:
    """Simple serial test for 2-bit patterns: 00, 01, 10, 11."""
    data = _clean_bits(bits)
    n = len(data)
    if n < 2:
        raise ValueError("Need at least 2 bits for serial test")

    pairs = [data[i : i + 2] for i in range(n - 1)]
    counts = Counter(pairs)

    total = len(pairs)
    expected = total / 4.0
    chi_square = 0.0
    for pair in ["00", "01", "10", "11"]:
        observed = counts.get(pair, 0)
        chi_square += ((observed - expected) ** 2) / expected

    # Approximation for df=3, enough for this educational dashboard.
    p_value = math.exp(-chi_square / 2.0)

    return {
        "name": "serial_m2",
        "n": n,
        "pairs_total": total,
        "counts": {k: counts.get(k, 0) for k in ["00", "01", "10", "11"]},
        "chi_square": chi_square,
        "p_value": p_value,
        "pass": p_value >= alpha,
    }


def run_basic_nist_suite(bits: str, alpha: float = 0.01) -> Dict[str, object]:
    """Run the 3 requested tests and return a frontend-friendly summary."""
    tests = [
        frequency_monobit_test(bits, alpha=alpha),
        runs_test(bits, alpha=alpha),
        serial_test_m2(bits, alpha=alpha),
    ]

    passed = sum(1 for test in tests if test["pass"])
    return {
        "alpha": alpha,
        "total_tests": len(tests),
        "passed_tests": passed,
        "all_pass": passed == len(tests),
        "tests": tests,
    }
