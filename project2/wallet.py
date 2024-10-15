import json
import jwt
import hashlib
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import os

VC_DIR = "VC"
KEYS_DIR = "VC_keys"

# Function to load the private key for signing the VP
def load_private_key(vc_name):
    with open(f"{KEYS_DIR}/{vc_name}_private.pem", "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# Function to hash claims for SD-JWT
def hash_claim(claim_value):
    claim_bytes = json.dumps(claim_value).encode('utf-8')
    return hashlib.sha256(claim_bytes).digest()

# Function to selectively disclose claims from VCs and create Verifiable Presentation
def create_verifiable_presentation(vc_names, selected_claims):
    now = datetime.utcnow()
    disclosed_claims = {}
    sd_digests = {}

    # Step 1: Load each VC and selectively disclose claims
    for vc_name in vc_names:
        with open(f"{VC_DIR}/{vc_name}.json", "r") as f:
            vc = json.load(f)['vc']
            decoded_vc = jwt.decode(vc, options={"verify_signature": False})  # Skip signature check for now
            
            for claim_key in selected_claims:
                if claim_key in decoded_vc['sd_digests']:
                    claim_hash = decoded_vc['sd_digests'][claim_key]
                    sd_digests[claim_key] = claim_hash

    # Step 2: Build the Verifiable Presentation (VP) payload
    vp_payload = {
        "iss": "https://wallet.example.com",
        "iat": int(now.timestamp()),
        "vp": {
            "type": "VerifiablePresentation",
            "sd_digests": sd_digests  # Include selectively disclosed claims
        }
    }

    # Step 3: Sign the VP (ES256) with the private key of one of the VCs
    private_key = load_private_key(vc_names[0])
    headers = {"alg": "ES256"}
    signed_vp = jwt.encode(vp_payload, private_key, algorithm="ES256", headers=headers)

    return signed_vp

# Example usage: Creating a Verifiable Presentation with selective disclosure
selected_claims = [
    "officialTravelDocExpiryDate",   # TravelAuth-specific claim
    "holdersName",                   # Common claim across VCs
    "issuerName",                    # Common claim across VCs
    "docNumberIdentifier",           # Common claim across VCs
    "placeOfIssueName",              # Common claim across VCs
    "birthdate"                      # Common claim across VCs
]

# Create Verifiable Presentation from Travel Auth, Visa, and ePassport
vp = create_verifiable_presentation(["travelAuth", "visa", "ePassport"], selected_claims)
print(f"Verifiable Presentation (SD-JWT): {vp}")
