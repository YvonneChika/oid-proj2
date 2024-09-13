import json
import jwt
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

# Load the schemas (adjust paths as needed)
with open('schemas/Digital_Travel_Authorization_VC_Schema.json', 'r') as schema_file:
    vc_schema = json.load(schema_file)

with open('schemas/Digital_Travel_Authorization_VC_Content_Schema.jsonld.json', 'r') as content_schema_file:
    vc_content_schema = json.load(content_schema_file)

# Step 1: Generate EC private key for signing
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Function to convert bytes to base64url format
def base64url_encode(input_bytes):
    return base64.urlsafe_b64encode(input_bytes).rstrip(b'=').decode('utf-8')

# Step 2: Extract public key components for the cnf claim (x, y coordinates)
public_numbers = public_key.public_numbers()
x_coordinate = base64url_encode(public_numbers.x.to_bytes(32, byteorder='big'))
y_coordinate = base64url_encode(public_numbers.y.to_bytes(32, byteorder='big'))

# Step 3: Hash claim for selective disclosure (SD-JWT)
def hash_claim(claim_value):
    claim_bytes = json.dumps(claim_value).encode('utf-8')  # Convert claim to bytes
    return hashlib.sha256(claim_bytes).digest().hex()  # Hash with SHA-256 and return the hex digest

# Step 4: Create a Verifiable Credential with _sd array for selective disclosure
def create_digital_travel_authorization_vc():
    now = datetime.utcnow()
    expiration = now + timedelta(days=365)

    # Accessing the "@context" from the "properties" field of the schema
    context = vc_schema["properties"]["@context"]["prefixItems"]

    # Sample claims
    claims = {
        "authorityDocName": "Travel Document",
        "birthdate": "1990-01-01",
        "detailedTypeText": "Tourist Visa",
        "entriesNumber": "1",
        "sexCode": "M",
        "identifyingNumberText": "A1234567",
        "natlCode": "USA",
        "officialTravelDocExpiryDate": "2030-01-01",
        "officialTravelDocHoldersName": "John Doe",
        "officialTravelDocIssuerName": "US Government",
        "officialTravelDocNumberIdentifier": "A1234567",
        "placeOfIssueName": "Washington DC",
        "validFromDate": "2024-01-01",
        "validUntilDate": "2024-12-31",
        "visibleDigitalSealNonConstrainedBinaryObject": "data:application/octet-stream;base64,....."
    }

    # Create the _sd array with hashed values
    sd_array = [hash_claim(value) for value in claims.values()]

    # Build the VC payload with the required claims and cnf
    vc_payload = {
        "@context": context,
        "type": vc_schema["properties"]["type"]["prefixItems"],
        "credentialSubject": {
            "id": "did:example:123456789abcdefghi",
            "digitalTravelAuthorization": {
                "_sd": sd_array  # Include hashed claims in the _sd array
            }
        },
        "_sd_alg": "sha-256",
        "iss": "https://issuer.example.com",
        "cnf": {
            "jwk": {
                "kty": "EC",     # Key type: Elliptic curve
                "crv": "P-256",  # Curve: P-256
                "x": x_coordinate,  # X-coordinate of the public key
                "y": y_coordinate   # Y-coordinate of the public key
            }
        },# Issuer of the VC
        "iat": int(now.timestamp()),  # Issued At (Unix time format)
        "exp": int(expiration.timestamp()),  # Expiration Time (Unix time format)
        "vct": "VerifiableCredential",
        "credentialSchema": {
            "id": vc_schema["$id"],
            "type": "JsonSchemaValidator2018"
        }        
    }

    # Return the VC payload and the original claims for disclosure purposes
    return vc_payload, claims

# Step 5: Sign the VC using SD-JWT and ES256, include "typ" in header
def sign_vc(vc_payload, private_key):
    headers = {
        "kid": "https://issuer.example.com/keys/1",  # Example key ID
        "typ": "vc+sd-jwt"  # Specify the JWT type as "vc+sd-jwt"
    }

    # Encode the payload with headers
    encoded_jwt = jwt.encode(vc_payload, private_key, algorithm="ES256", headers=headers)
    return encoded_jwt

# Step 6: Issue Verifiable Credential
if __name__ == "__main__":
    vc, claims = create_digital_travel_authorization_vc()  # Generate VC with _sd array
    signed_vc = sign_vc(vc, private_key)  # Sign the VC

    # Output the signed VC and claims
    print("Verifiable Credential (Signed):")
    print(signed_vc)

    print("\nClaims for selective disclosure:")
    print(json.dumps(claims, indent=2))

    # Example: Verifying the token
    try:
        decoded_vc = jwt.decode(signed_vc, public_key, algorithms=["ES256"])
        print("\nVerified VC:")
        print(json.dumps(decoded_vc, indent=2))
    except jwt.exceptions.InvalidSignatureError as e:
        print(f"Invalid signature: {e}")
