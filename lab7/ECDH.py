from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

alice_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()

alice_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)
bob_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)

print(f"Alice's Shared Key: {alice_shared_key.hex()}")
print(f"Bob's Shared Key: {bob_shared_key.hex()}")


assert alice_shared_key == bob_shared_key, "Key exchange failed"
print("Secure Key Exchange Successful")
