import random
import math
from .pa9_birthday import toy_hash

def naive_birthday_attack_history(n_bits: int, max_iter: int = 2000):
    """
    Runs naive birthday attack and returns the full history of (x, hash) pairs.
    Limited to 2000 iterations to avoid huge responses.
    """
    modulus = 1 << n_bits
    bound   = math.isqrt(modulus)
    seen    = {}
    history = []
    
    found = False
    collision = None
    
    for i in range(1, max_iter + 1):
        x = random.randrange(0, 2**32)
        h = toy_hash(x, n_bits)
        
        step = {"i": i, "x": x, "h": h}
        history.append(step)
        
        if h in seen and seen[h] != x:
            found = True
            collision = {
                "msg_a": seen[h],
                "msg_b": x,
                "hash_val": h,
                "iterations": i,
                "birthday_bound": bound,
                "ratio": round(i / bound, 3)
            }
            break
        
        seen[h] = x
        
    return {
        "found": found,
        "collision": collision,
        "history": history,
        "n_bits": n_bits,
        "birthday_bound": bound
    }
