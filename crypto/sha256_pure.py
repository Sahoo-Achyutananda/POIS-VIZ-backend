import struct

# Initial hash values
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

_H_original = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sig0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sig1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sig0_small(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sig1_small(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def generate_padding(msg_len_bytes):
    # standard SHA-256 padding for a specific length
    l = msg_len_bytes * 8
    q = (448 - l - 1) % 512
    padding = b'\x80' + b'\x00' * (q // 8) + struct.pack(">Q", l)
    return padding

class PureSHA256:
    def __init__(self, data=b"", initial_state=None, total_len=0):
        if initial_state is not None:
            self._h = list(initial_state)
        else:
            self._h = list(_H_original)
            
        self._unprocessed = b""
        self._message_byte_length = total_len
        self.update(data)

    def _process_chunk(self, chunk):
        w = [0] * 64
        for i in range(16):
            w[i] = struct.unpack(b'>I', chunk[i * 4:(i + 1) * 4])[0]
        for i in range(16, 64):
            w[i] = (sig1_small(w[i - 2]) + w[i - 7] + sig0_small(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h_val = self._h

        for i in range(64):
            t1 = (h_val + sig1(e) + ch(e, f, g) + _K[i] + w[i]) & 0xFFFFFFFF
            t2 = (sig0(a) + maj(a, b, c)) & 0xFFFFFFFF
            h_val = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self._h[0] = (self._h[0] + a) & 0xFFFFFFFF
        self._h[1] = (self._h[1] + b) & 0xFFFFFFFF
        self._h[2] = (self._h[2] + c) & 0xFFFFFFFF
        self._h[3] = (self._h[3] + d) & 0xFFFFFFFF
        self._h[4] = (self._h[4] + e) & 0xFFFFFFFF
        self._h[5] = (self._h[5] + f) & 0xFFFFFFFF
        self._h[6] = (self._h[6] + g) & 0xFFFFFFFF
        self._h[7] = (self._h[7] + h_val) & 0xFFFFFFFF

    def update(self, arg):
        if isinstance(arg, str):
            arg = arg.encode()
        self._unprocessed += arg
        self._message_byte_length += len(arg)
        
        while len(self._unprocessed) >= 64:
            self._process_chunk(self._unprocessed[:64])
            self._unprocessed = self._unprocessed[64:]

    def digest(self):
        message = self._unprocessed
        l = self._message_byte_length * 8
        message += b'\x80'
        message += b'\x00' * ((56 - (self._message_byte_length + 1) % 64) % 64)
        message += struct.pack(b'>Q', l)
        
        h_copy = list(self._h)
        for i in range(0, len(message), 64):
            self._process_chunk(message[i:i+64])
            
        result = b"".join(struct.pack(b'>I', val) for val in self._h)
        self._h = h_copy  # restore state
        return result

    def hexdigest(self):
        return self.digest().hex()

def sha256_length_extend(original_tag_hex: str, length_of_original_message: int, suffix: bytes) -> str:
    """
    Given the original hash (tag) and the total length of the original MAC payload `k || m` (in bytes),
    calculate the new hash over `k || m || PADDING || suffix` without knowing `k`.
    """
    state_bytes = bytes.fromhex(original_tag_hex)
    initial_state = struct.unpack(">8I", state_bytes)
    
    # Calculate length of the payload exactly as the hasher left it when it processed the original message.
    # The original hasher processed `k||m` and its padding.
    orig_pad = generate_padding(length_of_original_message)
    total_length_before_suffix = length_of_original_message + len(orig_pad)
    
    hasher = PureSHA256(initial_state=initial_state, total_len=total_length_before_suffix)
    hasher.update(suffix)
    return hasher.hexdigest()
