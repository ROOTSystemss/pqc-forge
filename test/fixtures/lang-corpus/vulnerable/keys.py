from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def make_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed = Ed25519PrivateKey.generate()
    return rsa_key, ec_key, ed