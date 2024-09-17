from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

def load_private_key():
    # Generate an EC private key (P-256)
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def load_public_key():
    # Load the public key (for the verifier)
    # In real cases, this would be provided by the issuer or extracted from the VC
    private_key = load_private_key()
    return private_key.public_key()
