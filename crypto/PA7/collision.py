def find_xor_collision(msg_bytes: bytes) -> bytes:
    """
    Given a message msg, finds another message msg' of the same length
    that collides with it under the XOR-based dummy_compress.
    
    Formula: h(z, m) = z ^ m_low ^ m_high
    We shift m_low and m_high to obtain a different m' with same XOR sum.
    """
    if len(msg_bytes) < 8:
        # If too short, just return something that works for at least 1 block
        base = msg_bytes.ljust(8, b"\x00")
    else:
        base = msg_bytes
        
    # Take first block
    b0 = bytearray(base[:8])
    # Swap first 4 and last 4 bytes
    b0_low = b0[:4]
    b0_high = b0[4:]
    
    # If they are already the same, we need another trick.
    if b0_low == b0_high:
        # Flip a bit in both halves
        b0_low[0] ^= 0x01
        b0_high[0] ^= 0x01
        
    new_b0 = b0_high + b0_low
    return bytes(new_b0) + base[8:]
