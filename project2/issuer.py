import os
import json
import hashlib
import base64  
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

VC_DIR = "VC"
KEYS_DIR = "VC_keys"

# Ensure directories exist
os.makedirs(VC_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# Function to generate EC key pairs
def generate_keys(vc_name):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Save private key
    private_key_path = os.path.join(KEYS_DIR, f"{vc_name}_private.pem")
    with open(private_key_path, "wb") as key_file:
        key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    public_key_path = os.path.join(KEYS_DIR, f"{vc_name}_public.pem")
    with open(public_key_path, "wb") as key_file:
        key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key_path, public_key_path

# Function to hash claims for SD-JWT
def hash_claim(claim_value):
    claim_bytes = json.dumps(claim_value).encode('utf-8')
    return hashlib.sha256(claim_bytes).digest()

# Function to create and sign SD-JWT Verifiable Credentials
def create_sd_jwt_vc(vc_name, vc_data):
    private_key_path, _ = generate_keys(vc_name)
    
    # Load the private key
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    now = datetime.utcnow()
    expiration = now + timedelta(days=365)

    # Step 1: Hash claims for selective disclosure
    sd_digests = {}
    for claim_key, claim_value in vc_data.items():
        claim_hash = hash_claim(claim_value)
        sd_digests[claim_key] = base64.urlsafe_b64encode(claim_hash).decode('utf-8')  # base64 encoding

    # Step 2: Build SD-JWT payload
    vc_payload = {
        "iss": f"https://issuer.example.com/{vc_name}",
        "iat": int(now.timestamp()),
        "exp": int(expiration.timestamp()),
        "sd_digests": sd_digests  # The claims in hashed form
    }

    # Step 3: Sign the SD-JWT
    headers = {"alg": "ES256"}
    signed_sd_jwt = jwt.encode(vc_payload, private_key, algorithm="ES256", headers=headers)

    # Save the issued VC
    with open(os.path.join(VC_DIR, f"{vc_name}.json"), "w") as f:
        json.dump({"vc": signed_sd_jwt}, f)

    return signed_sd_jwt

# Issue each VC based on schema with all required claims
def issue_vcs():
    # Travel Authorization VC - Schema-Based Claims
    travel_auth_data = {
        "authorityDocName": "Digital Travel Document",
        "birthdate": "1985-07-15",
        "detailedTypeText": "Tourist Visa",
        "entriesNumber": "12345",
        "sexCode": "F",
        "identifyingNumberText": "V567890",
        "natlCode": "USA",
        "officialTravelDocExpiryDate": "2025-12-31",
        "officialTravelDocHoldersName": "Jane Smith",
        "officialTravelDocIssuerName": "US Government",
        "officialTravelDocNumberIdentifier": "V567890",
        "placeOfIssueName": "New York",
        "validFromDate": "2020-12-30",
        "validUntilDate": "2025-12-31"
    }
    create_sd_jwt_vc("travelAuth", travel_auth_data)

    # Visa VC - Schema-Based Claims
    visa_data = {
        "birthdate": "1985-07-15",
        "docNumberIdentifier": "AB123456",
        "holdersName": "Jane Smith",
        "issuerName": "Canadian Immigration Office",
        "natlCode": "CAN",
        "sexCode": "F",			
        "typeCode": "Tourist Visa",
        "validFromDate": "2021-01-01",
        "validUntilDate": "2025-12-31"
    }
    create_sd_jwt_vc("visa", visa_data)

    # ePassport VC - Schema-Based Claims
    epassport_data = {
        "birthdate": "1985-07-15",
        "docTypeCode": "P",
        "expiryDate": "2030-12-31",
        "sexCode": "F",
        "holdersName": "Jane Smith",
        "issuerCode": "USA123",
        "nationality": "USA",
        "passportNumberIdentifier": "YMN123456"
    }
    create_sd_jwt_vc("ePassport", epassport_data)

    print("Verifiable Credentials issued and saved in VC folder.")

# Run the issuance process
issue_vcs()
