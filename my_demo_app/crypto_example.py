
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

# Generate a traditional RSA key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Calculate a SHA-256 hash
message = b"Hello QuantumShield"
digest = hashlib.sha256(message).hexdigest()

print("Demo completed")
