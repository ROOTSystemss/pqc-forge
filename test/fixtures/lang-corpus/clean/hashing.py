import hashlib
import secrets

# rsa.generate_private_key(public_exponent=65537, key_size=2048)  (commented out, not live)
def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest() + secrets.token_hex(8)