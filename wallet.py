import json
import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# Load the VC that was issued earlier (VC.json)
with open("VC.json", "r") as vc_file:
    verifiable_credential = json.load(vc_file)

# Generate EC key pair (ES256 with P-256)
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Base64url encode function for public key coordinates
def base64url_encode(input_bytes):
    return base64.urlsafe_b64encode(input_bytes).rstrip(b'=').decode('utf-8')

# Construct the Verifiable Presentation (VP)
def create_verifiable_presentation(vc):
    now = datetime.utcnow()
    expiration = now + timedelta(minutes=30)

    # Extract public key parameters for cnf (proof of possession)
    public_numbers = public_key.public_numbers()
    x = base64url_encode(public_numbers.x.to_bytes(32, byteorder="big"))
    y = base64url_encode(public_numbers.y.to_bytes(32, byteorder="big"))

    vp_payload = {
        "iss": "did:example:wallet",  # The wallet's DID
        "iat": int(now.timestamp()),  # Issued at
        "exp": int(expiration.timestamp()),  # Expiry time
        "aud": "https://verifier.example.com",  # Audience (Verifier's URL)
        "vp": {
            "verifiableCredential": vc,  # Include the VC from VC.json
        },
        "cnf": {
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
            }
        }
    }

    # Sign the Verifiable Presentation using SD-JWT (ES256)
    headers = {
        "typ": "vp+sd-jwt",  # Type: Verifiable Presentation using SD-JWT
        "alg": "ES256"
    }
    signed_vp = jwt.encode(vp_payload, private_key, algorithm="ES256", headers=headers)

    return signed_vp

# Simulate sending the Verifiable Presentation to the Verifier
def send_vp_to_verifier(vp):
    verifier_url = "http://verifier.example.com/verify"  # Verifier's endpoint
    headers = {"Content-Type": "application/jwt"}
    response = requests.post(verifier_url, data=vp, headers=headers)
    return response.status_code, response.text

if __name__ == "__main__":
    # Create and send VP
    vp = create_verifiable_presentation(verifiable_credential)
    status_code, response = send_vp_to_verifier(vp)

    print(f"Response from Verifier (status {status_code}):")
    print(response)
