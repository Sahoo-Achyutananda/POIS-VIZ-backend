import struct

def md_pad(message: bytes, block_size: int = 8) -> bytes:
    """
    Applies Merkle-Damgard strengthening padding.
    1. Appends 1 bit (0x80 byte)
    2. Appends enough 0 bits so that the total padded length is congruent to (block_size - 8) mod block_size.
       Since block_size=8 here, block_size - 8 = 0. Meaning it pads to a multiple of 8, then appends 8 length bytes.
    3. Appends 64-bit big-endian representation of ORIGINAL MESSAGE LENGTH IN BITS.
    """
    original_bit_length = len(message) * 8
    
    padded = bytearray(message)
    padded.append(0x80)
    
    # We need to leave exactly 8 bytes at the end for the length.
    # So we pad with zeros until (len(padded) + 8) % block_size == 0
    while (len(padded) + 8) % block_size != 0:
        padded.append(0x00)
        
    padded.extend(struct.pack(">Q", original_bit_length))
    return bytes(padded)

def dummy_compress(chain_val: bytes, m_block: bytes) -> bytes:
    """
    A toy 4-byte output, 8-byte input compression function.
    Splits m_block into two 4-byte halves and XORs them with the chain_val.
    """
    m1 = m_block[:4]
    m2 = m_block[4:]
    return bytes([c ^ x ^ y for c, x, y in zip(chain_val, m1, m2)])

def chunk_message(message: bytes, block_size: int = 8) -> list[bytes]:
    padded = md_pad(message, block_size)
    return [padded[i:i+block_size] for i in range(0, len(padded), block_size)]

def compute_chain(blocks: list[bytes]) -> list[dict]:
    """
    Computes the MD hash chain over a list of blocks and returns the visualization trace.
    Default IV is 4 bytes of 0x00.
    """
    z = b"\x00\x00\x00\x00"
    trace = []
    
    for idx, m_block in enumerate(blocks):
        z_out = dummy_compress(z, m_block)
        trace.append({
            "index": idx,
            "z_in_hex": z.hex(),
            "m_hex": m_block.hex(),
            "z_out_hex": z_out.hex()
        })
        z = z_out
        
    return trace
