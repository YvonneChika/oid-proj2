import jwt
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
from cryptography.hazmat.primitives import hashes

# Load Verifiable Credential from JSON file
def load_vc(vc_path='VC.json'):
    with open(vc_path, 'r') as f:
        return json.load(f)

# Create SD-JWT by hashing sensitive data
def create_sd_jwt(vc):
    sensitive_data = vc['credentialSubject']['digitalTravelAuthorization']['_sd']

    # Hash the sensitive data using SHA-256
    sd_hashed = [hashlib.sha256(data.encode('utf-8')).hexdigest() for data in sensitive_data]

    # Payload for SD-JWT
    payload = {
        "iss": vc["iss"],
        "iat": vc["iat"],
        "exp": vc["exp"],
        "_sd": sd_hashed  # Hashed claims (sensitive data)
    }

    return payload

# Sign JWT with ES256 (P-256 curve)
def sign_es256(payload, private_key):
    token = jwt.encode(payload, private_key, algorithm='ES256')
    return token

# Attach Proof to the Verifiable Credential (VP creation)
def create_verifiable_presentation(vc, sd_jwt_token):
    vp = {
        "verifiableCredential": vc,
        "proof": {
            "type": "ES256",
            "jwt": sd_jwt_token
        }
    }
    return vp

# Generate EC key pair (P-256)
def generate_ec_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key

# NEW: Load public and private keys from files (PEM format)
def load_keys(private_key_path, public_key_path):
    # Load the private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Load the public key
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
        )

    return private_key, public_key

# Verify ES256 JWT using the public key
def verify_es256(token, public_key):
    return jwt.decode(token, public_key, algorithms=['ES256'])
