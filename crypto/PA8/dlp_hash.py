import hashlib
from typing import List, Dict, Optional

def mod_exp(base: int, exponent: int, modulus: int) -> int:
    return pow(base, exponent, modulus)

class DLPGroup:
    def __init__(self, p: int, q: int, g: int, h_hat: int):
        self.p = p # Safe prime
        self.q = q # Subgroup order (prime)
        self.g = g # Base 1
        self.h_hat = h_hat # Base 2 (h_hat = g^alpha mod p)

    def compress_full(self, z: int, m: int) -> Dict[str, int]:
        """h(z, m) = (g^z * h_hat^m) mod p. Returns intermediate values."""
        g_z = mod_exp(self.g, z, self.p)
        h_m = mod_exp(self.h_hat, m, self.p)
        return {
            "g_z": g_z,
            "h_m": h_m,
            "res": (g_z * h_m) % self.p
        }

P_256 = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCB
# Not using real 1024 yet
# We'll use a smaller 64-bit safe prime for general demo and a 16-bit one for anniversary attack.

# 64-bit Safe Prime
# q = 9223372036854775837 (prime)
# p = 18446744073709551616 bit...
# Let's use a smaller one:
P_MAIN = 143165575127 # p
Q_MAIN = 71582787563 # q = (p-1)/2
G_MAIN = 2
H_HAT_MAIN = 123456789 # Hardcoded hat_h for consistency

# Toy Parameters (16-bit approx)
P_TOY = 65539
Q_TOY = 32769 # Not a prime... 
# Let's use p=131071 (Mersenne prime M17 is 2^17-1, not q)
# p = 65537 is prime? Yes (Fermat). But we need q=(p-1)/2 prime.
# q=32749, 2q+1 = 65499 (3 divides)
# p=65519 (prime), q=32759 (prime). YES!
P_TOY = 65519
Q_TOY = 32759
G_TOY = 7
H_HAT_TOY = 12345

production_group = DLPGroup(P_MAIN, Q_MAIN, G_MAIN, H_HAT_MAIN)
toy_group = DLPGroup(P_TOY, Q_TOY, G_TOY, H_HAT_TOY)

def int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')

def dlp_hash_trace(message: str, use_toy: bool = False) -> Dict:
    from crypto.PA7.md import md_pad, chunk_message
    
    group = toy_group if use_toy else production_group
    # Each block is mapped to Z_q. 
    # For P_MAIN (~37 bits), we can use 4-byte blocks.
    block_size = 4 if not use_toy else 2
    
    msg_bytes = message.encode('utf-8')
    blocks = chunk_message(msg_bytes, block_size)
    
    # IV should be an element of G. Let's use g = 2.
    z = group.g 
    trace = []
    
    for idx, m_block in enumerate(blocks):
        m_val = bytes_to_int(m_block) % group.q
        full_res = group.compress_full(z, m_val)
        z_out = full_res["res"]
        
        trace.append({
            "index": idx,
            "z_in": z,
            "z_in_hex": hex(z),
            "m_val": m_val,
            "m_hex": m_block.hex(),
            "g_z": full_res["g_z"],
            "g_z_hex": hex(full_res["g_z"]),
            "h_m": full_res["h_m"],
            "h_m_hex": hex(full_res["h_m"]),
            "z_out": z_out,
            "z_out_hex": hex(z_out),
            "formula": f"{group.g}^{z} * {group.h_hat}^{m_val} mod {group.p}"
        })
        z = z_out
        
    return {
        "trace": trace,
        "final_hash": hex(z),
        "params": {
            "p": group.p,
            "q": group.q,
            "g": group.g,
            "h_hat": group.h_hat
        }
    }

def birthday_attack_hunt(target_bits: int = 16):
    """
    Simulated birthday attack for the toy demo.
    Finds a collision in DLP_Hash (toy version).
    """
    import random
    seen = {} # hash -> message
    
    # We'll limit the search to avoid hanging the server
    for i in range(10000):
        # Random message
        msg = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10))
        h_res = dlp_hash_trace(msg, use_toy=True)
        h_val = h_res["final_hash"]
        
        if h_val in seen:
            if seen[h_val] != msg:
                return {
                    "collision_found": True,
                    "msgA": seen[h_val],
                    "msgB": msg,
                    "hash": h_val,
                    "iterations": i
                }
        seen[h_val] = msg
        
    return {"collision_found": False}
