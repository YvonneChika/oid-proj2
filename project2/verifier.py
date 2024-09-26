import jwt
import json
from cryptography.hazmat.primitives import serialization

# Load the public key from the Wallet to verify the JWT
def load_public_key(path):
    with open(path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key

# Function to create a Verifier Request (for a presentation)
def create_verifier_request():
    nonce = "unique_nonce_value"  # Example nonce
    presentation_request = {
        "iss": "https://verifier.example.com",
        "aud": "https://wallet.example.com",
        "nonce": nonce,
        "iat": 1696876166,
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
    return presentation_request

# Function to validate the Verifiable Presentation
def validate_presentation(vp_token, public_key_path, expected_nonce, expected_audience):
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
