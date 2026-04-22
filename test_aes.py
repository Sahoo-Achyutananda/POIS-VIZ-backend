from crypto.prf import aes_block_encrypt
import time

print("Starting AES...")
start = time.time()
try:
    key_hex = "00112233445566778899aabbccddeeff"
    m_pad = bytes.fromhex("68656c6c6f20776f726c640000000000")
    print(f"Calling AES with key {key_hex} and block {m_pad.hex()}")
    out = aes_block_encrypt(key_hex, m_pad)
    print(f"Success! {out.hex()}")
except Exception as e:
    print(e)
print(time.time() - start)
