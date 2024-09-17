import jwt
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import hashlib
import base64
import urllib.parse

# Load the issuer's private key (from `oid4vc_issuer.py`) to sign the VP
def load_keys():
    with open("issuer_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None
        )
    with open("issuer_public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    return private_key, public_key

private_key, public_key = load_keys()

# Base64 URL-safe encoding function
def base64url_encode(input_bytes):
    return base64.urlsafe_b64encode(input_bytes).rstrip(b'=').decode('utf-8')

# Hash claim for selective disclosure (SD-JWT)
def hash_claim(claim_value):
    claim_bytes = json.dumps(claim_value).encode('utf-8')
    return hashlib.sha256(claim_bytes).digest().hex()

# Extract public key components (x, y) for the cnf claim
def get_public_key_components():
    public_numbers = public_key.public_numbers()
    x = base64url_encode(public_numbers.x.to_bytes(32, byteorder='big'))
    y = base64url_encode(public_numbers.y.to_bytes(32, byteorder='big'))
    return x, y

# Create Verifiable Presentation (VP) with SD-JWT and ES256
def create_verifiable_presentation(signed_vc, nonce, audience):
    now = datetime.utcnow()

    # Selectively disclose certain fields using SD-JWT (hashed claims)
    claims = {
        "authorityDocName": "Travel Document",
        "birthdate": "1990-01-01",
        "detailedTypeText": "Tourist Visa",
        "entriesNumber": "1",
        "sexCode": "M",
        "officialTravelDocHoldersName": "John Doe",
        "officialTravelDocIssuerName": "US Government",
        "officialTravelDocNumberIdentifier": "A1234567",
    }
    _sd = [hash_claim(value) for value in claims.values()]

    # Public key components for the confirmation (`cnf`) claim
    x, y = get_public_key_components()

    # Verifiable Presentation payload
    vp_payload = {
        "iss": "https://wallet.example.com",  # Issuer (Wallet)
        "iat": int(now.timestamp()),  # Issued at
        "_sd": _sd,  # Selectively disclosed claims (hashed)
        "vct": "VerifiableCredential",  # Verifiable Credential Type
        "_sd_alg": "sha-256",  # Algorithm used for SD-JWT (SHA-256)
        "cnf": {  # Confirmation claim containing the public key details
            "jwk": {
                "kty": "EC",  # Key type: Elliptic Curve
                "crv": "P-256",  # Curve type: P-256
                "x": x,  # X-coordinate of the public key
                "y": y   # Y-coordinate of the public key
            }
        },
        "nonce": nonce,  # Nonce from Verifier request
        "aud": audience,  # Audience (Verifier)
        "vp": {
            "type": "VerifiablePresentation",
            "verifiableCredential": [signed_vc],  # Signed Verifiable Credential
        }
    }

    # Sign the Verifiable Presentation using ES256 (ECDSA with SHA-256)
    headers = {
        "kid": "https://wallet.example.com/keys/1",  # Key identifier
        "typ": "vp+sd-jwt",  # Type as Verifiable Presentation using SD-JWT
        "alg": "ES256"
    }

    # Create the SD-JWT signed VP token (this is what will be stored in the proof)
    signed_vp_jwt = jwt.encode(vp_payload, private_key, algorithm="ES256", headers=headers)

    presentation_submission = {
            "definition_id": "vc-presentation",  # This is the ID from the Verifier's presentation_definition
            "descriptor_map": [
                {
                    "id": "vc-presentation",  # Reference to the input_descriptor ID from the Verifier's request
                    "format": "jwt_vc",  # Format of the Verifiable Credential
                    "path": "$.vp.verifiableCredential[0]"  # JSONPath that points to the Verifiable Credential
                }
            ]
        }
    
      # Encode the presentation_submission into a URL-safe string
    presentation_submission_encoded = urllib.parse.quote(json.dumps(presentation_submission))
   
    # Create the final VP with the proof
    # vp_with_proof = {
    #     "vp": {
    #         "type": "VerifiablePresentation",
    #         "verifiableCredential": [signed_vc],  # Include the signed VC in the VP
    #     },
    #     "proof": {  # Include the proof object
    #         "proof_type": "JwtProof",  # Type of proof
    #         "jwt": signed_vp_jwt  # The signed JWT token
    #     }
    # }

    # return vp_with_proof, presentation_submission_encoded  # Return the VP with the proof format

    return {
            "vp": {
                "type": "VerifiablePresentation",
                "verifiableCredential": [signed_vc]
            },
            "proof": {
                "proof_type": "JwtProof",
                "jwt": signed_vp_jwt  # Signed JWT containing the Verifiable Presentation
            },
            "presentation_submission": presentation_submission_encoded  # Encoded presentation_submission
        }