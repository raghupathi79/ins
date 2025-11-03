import random

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x

def is_prime(n):
    if n < 2: 
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0: 
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return ((e, n), (d, n)) #Public, private key

# --- Encryption & Decryption ---
def encrypt(msg, pubkey):
    e, n = pubkey
    return [pow(ord(ch), e, n) for ch in msg]

def decrypt(cipher, privkey):
    d, n = privkey
    return ''.join([chr(pow(c, d, n)) for c in cipher])

# --- Example ---
p, q = 61, 53
public, private = generate_keypair(p, q)
message = "HELLO"
cipher = encrypt(message, public)
print("Encrypted:", cipher)
print("Decrypted:", decrypt(cipher, private))