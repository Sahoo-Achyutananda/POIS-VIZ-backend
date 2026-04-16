import secrets
from crypto.PA3.cpa import cpa
from crypto.pa5_mac import PA5MAC

class CCASecure:
    def __init__(self):
        self.cpa_tool = cpa()

    def encrypt(self, ke_hex: str, km_hex: str, message: str) -> dict:
        """
        Encrypt-then-MAC (EtM):
        1. (r, c) = CPA.Enc(ke, m)
        2. t = MAC(km, r || c)
        Returns {r, c, t}
        """
        r_hex, c_hex = self.cpa_tool.encrypt(ke_hex, message)
        # We Mac the concatenation of r and c
        payload_hex = r_hex + c_hex
        tag_hex = PA5MAC.cbc_mac(km_hex, payload_hex)
        
        return {
            "r_hex": r_hex,
            "c_hex": c_hex,
            "tag_hex": tag_hex
        }

    def decrypt(self, ke_hex: str, km_hex: str, r_hex: str, c_hex: str, tag_hex: str) -> str:
        """
        Decrypt-then-MAC (EtM):
        1. Validate MAC(km, r || c) == t
        2. If invalid, return None (⊥)
        3. Else return CPA.Dec(ke, r, c)
        """
        payload_hex = r_hex + c_hex
        is_valid = PA5MAC.cbc_vrfy(km_hex, payload_hex, tag_hex)
        
        if not is_valid:
            return None # Represents ⊥
            
        try:
            plaintext = self.cpa_tool.decrypt(ke_hex, r_hex, c_hex)
            return plaintext
        except Exception:
            # Fallback if padding or decryption fails even if MAC was valid (rare in EtM)
            return None

    def malleability_test(self, ke_hex: str, km_hex: str, message: str, flip_bit_index: int) -> dict:
        """
        Compare CPA-only vs CCA (EtM) when a bit is flipped in the ciphertext.
        """
        # 1. Standard Encryption
        enc_res = self.encrypt(ke_hex, km_hex, message)
        r_hex = enc_res["r_hex"]
        c_hex = enc_res["c_hex"]
        t_hex = enc_res["tag_hex"]
        
        # 2. Modify ciphertext (bit flip)
        c_bytes = list(bytes.fromhex(c_hex))
        byte_idx = flip_bit_index // 8
        bit_pos = flip_bit_index % 8
        
        if flip_bit_index >= 0 and byte_idx < len(c_bytes):
            c_bytes[byte_idx] ^= (1 << (7 - bit_pos))
            
        c_hex_modified = bytes(c_bytes).hex()
        
        # 3. Decrypt CPA-only (ignoring MAC)
        try:
            cpa_dec = self.cpa_tool.decrypt(ke_hex, r_hex, c_hex_modified, strict_padding=False)
            cpa_status = "Decrypted (Malleable)"
        except Exception as e:
            cpa_dec = f"[Error: {str(e)}]"
            cpa_status = "Decryption Failed"

        # 4. Decrypt CCA (checking MAC)
        cca_dec = self.decrypt(ke_hex, km_hex, r_hex, c_hex_modified, t_hex)
        if cca_dec is None:
            cca_status = "Rejected (⊥) ✅"
            cca_result = "⊥ (MAC Failure)"
        else:
            cca_status = "Decrypted (Vulnerable?) ❌"
            cca_result = cca_dec
            
        return {
            "original_m": message,
            "modified_c_hex": c_hex_modified,
            "cpa": {
                "plaintext": cpa_dec,
                "status": cpa_status
            },
            "cca": {
                "plaintext": cca_result,
                "status": cca_status
            }
        }

# Global instance for IND-CCA2 Game
CCA_GAME_SERVER_KEY_E = secrets.token_hex(16)
CCA_GAME_SERVER_KEY_M = secrets.token_hex(16)
CCA_CHALLENGE_CID = None

def get_cca_challenge():
    global CCA_CHALLENGE_CID
    # random messages
    m0 = "Attack at Dawn"
    m1 = "Retreat now!!"
    b = secrets.choice([0, 1])
    m = m0 if b == 0 else m1
    cca = CCASecure()
    res = cca.encrypt(CCA_GAME_SERVER_KEY_E, CCA_GAME_SERVER_KEY_M, m)
    CCA_CHALLENGE_CID = res
    return {
        "m0": m0,
        "m1": m1,
        "challenge_ciphertext": res
    }
