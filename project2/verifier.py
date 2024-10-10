import jwt
import json
from cryptography.hazmat.primitives import serialization

# # Load the public key from the Wallet to verify the JWT
# def load_public_key(path):
#     with open(path, 'rb') as key_file:
#         public_key = serialization.load_pem_public_key(key_file.read())
#     return public_key

# # Function to create a Verifier Request (for a presentation)
# def create_verifier_request():
#     nonce = "unique_nonce_value"  # Example nonce
#     presentation_request = {
#         "iss": "https://verifier.example.com",
#         "aud": "https://wallet.example.com",
#         "nonce": nonce,
#         "iat": 1696876166,
#         "presentation_definition": {
#             "input_descriptors": [
#                 {
#                     "id": "travelAuth-descriptor",
#                     "schema": "https://schemas.prod.digitalcredentials.iata.org/DigitalTravelAuthorization.json"
#                 },
#                 {
#                     "id": "ePassport-descriptor",
#                     "schema": "https://schemas.prod.digitalcredentials.iata.org/epassport.json"
#                 },
#                 {
#                     "id": "visa-descriptor",
#                     "schema": "https://schemas.prod.digitalcredentials.iata.org/visa.json"
#                 }
#             ]
#         }
#     }
#     return presentation_request

# # Function to validate the Verifiable Presentation
# def validate_presentation(vp_token, public_key_path, expected_nonce, expected_audience):
#     public_key = load_public_key(public_key_path)

#     # Decode and validate the VP JWT
#     try:
#         decoded_vp = jwt.decode(vp_token, public_key, algorithms=["ES256"], audience=expected_audience)

#         # Validate nonce
#         if decoded_vp["nonce"] != expected_nonce:
#             raise Exception("Nonce mismatch!")

#         print("Verifiable Presentation validated successfully!")
#         return decoded_vp
#     except jwt.exceptions.InvalidSignatureError:
#         print("Invalid signature.")
#         return None
#     except jwt.exceptions.InvalidAudienceError:
#         print("Invalid audience.")
#         return None

import uuid
import urllib.parse

# Function to generate a dynamic deeplink with a request URI for the Wallet
def generate_deeplink():
    # Example dynamic client_id (could be based on DID or project configuration)
    client_id = "did:web:wallet.example.com"  # You can dynamically generate this or use a static value
    
    # Generate a unique request_uri for this example
    base_request_uri = "https://verifier.example.com/jwts/"
    unique_id = str(uuid.uuid4())  # Generate a unique ID for the request URI
    request_uri = base_request_uri + unique_id
    
    # Construct the full deeplink
    deeplink = f"openid-vc://?client_id={urllib.parse.quote(client_id)}&request_uri={urllib.parse.quote(request_uri)}"
    return deeplink

# Function to create a Presentation Request
def create_presentation_request():
    nonce = str(uuid.uuid4())  # Generate a unique nonce
    presentation_request = {
        "iss": "https://verifier.example.com",
        "aud": "https://wallet.example.com",
        "nonce": nonce,
        "iat": 1696876166,  # Example issue timestamp
        "presentation_definition": {
            "input_descriptors": [
                {
                    "id": "travelAuth-descriptor",
                    "schema": "https://schemas.prod.digitalcredentials.iata.org/DigitalTravelAuthorization.json"
                },
                {
                    "id": "ePassport-descriptor",
                    "schema": "https://schemas.prod.digitalcredentials.iata.org/epassport.json"
                },
                {
                    "id": "visa-descriptor",
                    "schema": "https://schemas.prod.digitalcredentials.iata.org/visa.json"
                }
            ]
        }
    }
    return presentation_request, nonce

# Function to validate the Verifiable Presentation (VP) sent by the Wallet
def validate_presentation(vp_token, public_key_path, expected_nonce, expected_audience):
    from cryptography.hazmat.primitives import serialization
    import jwt

    # Load the public key from the Wallet to verify the JWT
    def load_public_key(path):
        with open(path, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
        return public_key

    public_key = load_public_key(public_key_path)

    # Decode and validate the VP JWT
    try:
        decoded_vp = jwt.decode(vp_token, public_key, algorithms=["ES256"], audience=expected_audience)

        # Validate nonce
        if decoded_vp["nonce"] != expected_nonce:
            raise Exception("Nonce mismatch!")

        print("Verifiable Presentation validated successfully!")
        return decoded_vp
    except jwt.exceptions.InvalidSignatureError:
        print("Invalid signature.")
        return None
    except jwt.exceptions.InvalidAudienceError:
        print("Invalid audience.")
        return None
