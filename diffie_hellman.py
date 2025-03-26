from init import *

# Private keys
alice_private = generate_private_key()
bob_private = generate_private_key()
mallory_private = generate_private_key()  # MITM attacker

# Public keys
alice_public = generate_public_key(alice_private)
bob_public = generate_public_key(bob_private)
mallory_public = generate_public_key(mallory_private)

# Shared keys (normal communication)
alice_shared_key = generate_shared_key(bob_public, alice_private)
bob_shared_key = generate_shared_key(alice_public, bob_private)

# Shared keys (under attack)
alice_mallory_shared = generate_shared_key(mallory_public, alice_private)
bob_mallory_shared = generate_shared_key(mallory_public, bob_private)