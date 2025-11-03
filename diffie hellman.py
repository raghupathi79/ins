import random

p = 23   # Prime number
g = 5    # Primitive root modulo p (hcf 1 with p)

# Step 2: Alice chooses her private key (a) and computes her public key (A)
a = random.randint(1, p - 1)
A = pow(g, a, p)   # A = g^a mod p
print(f"Alice's private key (a): {a}")
print(f"Alice's public key (A): {A}\n")

# Step 3: Bob chooses his private key (b) and computes his public key (B)
b = random.randint(1, p - 1)
B = pow(g, b, p)   # B = g^b mod p
print(f"Bob's private key (b): {b}")
print(f"Bob's public key (B): {B}\n")

# Step 4: Exchange public keys (A and B) over insecure channel

# Step 5: Each side computes the shared secret key
shared_secret_Alice = pow(B, a, p)   # (B^a) mod p
shared_secret_Bob = pow(A, b, p)     # (A^b) mod p

print(f"Alice's computed shared secret: {shared_secret_Alice}")
print(f"Bob's computed shared secret:   {shared_secret_Bob}\n")

if shared_secret_Alice == shared_secret_Bob:
    print("✅ Secure shared key established successfully!")
else:
    print("❌ Shared key mismatch! Check implementation.")