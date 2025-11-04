# Pure-Python SHA-256 implementation
# Works with Python 3.x

from typing import ByteString

# Constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
H0_INIT = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

MASK_32 = 0xFFFFFFFF

def _right_rotate(x: int, n: int) -> int:
    """Right rotate a 32-bit integer x by n bits."""
    return ((x >> n) | (x << (32 - n))) & MASK_32

def sha256(data: ByteString) -> str:
    """
    Compute SHA-256 digest of input bytes and return hexadecimal string.
    data: bytes-like object (e.g., b'hello').
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")

    # 1. Pre-processing (padding)
    msg = bytearray(data)
    orig_bit_len = len(msg) * 8
    # append a single '1' bit (0x80)
    msg.append(0x80)
    # append '0' bits until message length in bytes mod 64 == 56
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    # append original message length as 64-bit big-endian integer
    msg += orig_bit_len.to_bytes(8, 'big')

    # 2. Initialize hash values
    h = H0_INIT.copy()

    # 3. Process the message in successive 512-bit (64-byte) chunks
    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]
        # create a 64-entry message schedule array w[0..63] of 32-bit words
        w = [0] * 64
        # first 16 words are from the chunk
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:(i+1)*4], 'big')
        # extend the remaining words
        for i in range(16, 64):
            s0 = (_right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)) & MASK_32
            s1 = (_right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)) & MASK_32
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & MASK_32

        # Initialize working variables with current hash value
        a, b, c, d, e, f, g, h_work = h

        # Main compression function
        for i in range(64):
            S1 = (_right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)) & MASK_32
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h_work + S1 + ch + K[i] + w[i]) & MASK_32
            S0 = (_right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)) & MASK_32
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & MASK_32

            h_work = g
            g = f
            f = e
            e = (d + temp1) & MASK_32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & MASK_32

        # Add the compressed chunk to the current hash value
        h = [
            (h[0] + a) & MASK_32,
            (h[1] + b) & MASK_32,
            (h[2] + c) & MASK_32,
            (h[3] + d) & MASK_32,
            (h[4] + e) & MASK_32,
            (h[5] + f) & MASK_32,
            (h[6] + g) & MASK_32,
            (h[7] + h_work) & MASK_32,
        ]

    # Produce the final hash value (big-endian) as hex
    return ''.join(f'{value:08x}' for value in h)


# Demo / quick test
if __name__ == "__main__":
    import hashlib

    tests = [b'', b'abc', b'hello world', b'The quick brown fox jumps over the lazy dog']
    for t in tests:
        my = sha256(t)
        lib = hashlib.sha256(t).hexdigest()
        print(f"input: {t!r}")
        print(f"sha256 (this impl): {my}")
        print(f"sha256 (hashlib) : {lib}")
        print("match:", my == lib)
        print("-" * 60)

