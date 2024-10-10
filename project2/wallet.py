# import json
# import jwt
# import hashlib
# import base64
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.backends import default_backend
# from datetime import datetime, timedelta
# import os
# import urllib.parse

# # Load the private key to sign the Verifiable Presentation
# def load_private_key(path):
#     with open(path, 'rb') as key_file:
#         private_key = serialization.load_pem_private_key(key_file.read(), password=None)
#     return private_key

# # Function to hash claims for selective disclosure (SD-JWT)
# def hash_claim(claim_value):
#     claim_bytes = json.dumps(claim_value).encode('utf-8')
#     return hashlib.sha256(claim_bytes).hexdigest()

# # Function to load Verifiable Credential from a JSON file
# def load_credential(file_path):
#     with open(file_path, 'r') as cred_file:
#         return json.load(cred_file)

# # Function to create a Verifiable Presentation
# # Function to create a Verifiable Presentation
# def create_verifiable_presentation():
#     credentials_dir = 'credentials/'
#     keys_dir = 'keys/'

#     # Load all three credentials
#     travel_auth_cred = load_credential(os.path.join(credentials_dir, 'travelAuth.json'))
#     epassport_cred = load_credential(os.path.join(credentials_dir, 'ePassport.json'))
#     visa_cred = load_credential(os.path.join(credentials_dir, 'visa.json'))

#     # Combine essential information from the credentials (for this example, we just include the whole credential)
#     combined_vc_data = {
#         "travelAuth": travel_auth_cred,
#         "ePassport": epassport_cred,
#         "visa": visa_cred
#     }

#     # Load the private key for signing the Verifiable Presentation
#     private_key_path = os.path.join(keys_dir, 'travelAuth_private.pem')  # Example key
#     private_key = load_private_key(private_key_path)

#     # Build the Verifiable Presentation payload
#     now = datetime.utcnow()
#     vp_payload = {
#         "iss": "https://wallet.example.com",  # Issuer (Wallet)
#         "iat": int(now.timestamp()),  # Issued at timestamp
#         "nonce": "unique_nonce_value",  # Example nonce
#         "aud": "https://verifier.example.com",  # Audience (Verifier)
#         "vp": {
#             "type": "VerifiablePresentation",
#             "verifiableCredential": combined_vc_data
#         }
#     }

#     # Header for the SD-JWT VP
#     headers = {
#         "kid": "https://wallet.example.com/keys/1",
#         "typ": "vp+sd-jwt",
#         "alg": "ES256"
#     }

#     # Sign the VP using SD-JWT and return the signed token
#     signed_vp_jwt = jwt.encode(vp_payload, private_key, algorithm="ES256", headers=headers)
    
#     return signed_vp_jwt


# # Encode the Verifiable Presentation in URL-safe format for transmission
# def encode_presentation(vp_token):
#     return urllib.parse.quote(vp_token)

import json
import jwt
import hashlib
import uuid
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import os
import urllib.parse

# Load the private key to sign the Verifiable Presentation
def load_private_key(path):
    with open(path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    return private_key

# Function to hash claims for selective disclosure (SD-JWT)
def hash_claim(claim_value):
    claim_bytes = json.dumps(claim_value).encode('utf-8')
    return hashlib.sha256(claim_bytes).hexdigest()

# Function to load Verifiable Credential from a JSON file
def load_credential(file_path):
    with open(file_path, 'r') as cred_file:
        return json.load(cred_file)

# Function to create a Verifiable Presentation
def create_verifiable_presentation():
    credentials_dir = 'credentials/'
    keys_dir = 'keys/'

    # Load all three credentials
    travel_auth_cred = load_credential(os.path.join(credentials_dir, 'travelAuth.json'))
    epassport_cred = load_credential(os.path.join(credentials_dir, 'ePassport.json'))
    visa_cred = load_credential(os.path.join(credentials_dir, 'visa.json'))

    # Combine essential information from the credentials
    combined_vc_data = {
        "travelAuth": travel_auth_cred,
        "ePassport": epassport_cred,
        "visa": visa_cred
    }

    # Generate a unique nonce using uuid
    nonce = str(uuid.uuid4())

    # Load the private key for signing the Verifiable Presentation
    private_key_path = os.path.join(keys_dir, 'travelAuth_private.pem')
    private_key = load_private_key(private_key_path)

    # Build the Verifiable Presentation payload
    now = datetime.utcnow()
    vp_payload = {
        "iss": "https://wallet.example.com",  # Issuer (Wallet)
        "iat": int(now.timestamp()),  # Issued at timestamp
        "nonce": nonce,  # Auto-generated nonce
        "aud": "https://verifier.example.com",  # Audience (Verifier)
        "vp": {
            "type": "VerifiablePresentation",
            "verifiableCredential": combined_vc_data
        }
    }

    # Header for the SD-JWT VP
    headers = {
        "kid": "https://wallet.example.com/keys/1",
        "typ": "vp+sd-jwt",
        "alg": "ES256"
    }

    # Sign the VP using SD-JWT and return the signed token
    signed_vp_jwt = jwt.encode(vp_payload, private_key, algorithm="ES256", headers=headers)
    
    return signed_vp_jwt, nonce  # Return the signed token and nonce for later validation