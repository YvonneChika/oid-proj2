import jwt
import json
import uuid  # To generate dynamic nonce
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import urllib.parse

# Load the issuer's public key to verify VP signatures
def load_public_key():
    with open("issuer_public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

public_key = load_public_key()

# Function to create a Verifier Request, which includes a dynamic nonce and audience
def create_verifier_request():
    nonce = str(uuid.uuid4())  # Generate a unique nonce
    verifier_request = {
        "iss": "https://verifier.example.com",
        "aud": "https://wallet.example.com",
        "nonce": nonce,
        "iat": 1696876166,  # Issued at timestamp
        "presentation_definition": {
            "input_descriptors": [
                {
                    "id": "vc-presentation",
                    "schema": [
                        {
                            "uri": "https://www.w3.org/2018/credentials/v1"
                        }
                    ],
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.type"],
                                "filter": {
                                    "type": "string",
                                    "const": "VerifiableCredential"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
    return verifier_request, nonce

# Function to validate Verifiable Presentation (VP)
def validate_presentation(presentation_response, expected_nonce, expected_audience):
    try:
        # Ensure presentation_response is a dictionary and contains necessary keys
        if not isinstance(presentation_response, dict):
            raise Exception("Invalid presentation_response format, expected dictionary.")

        # Extract the JWT from the proof object
        proof = presentation_response.get("proof")
        if not proof or not isinstance(proof, dict):
            raise Exception("Missing or invalid proof in presentation_response.")

        proof_jwt = proof.get("jwt")
        if not proof_jwt:
            raise Exception("JWT missing in the proof object.")

        # Decode the JWT using the public key, and validate audience and nonce
        decoded_vp = jwt.decode(proof_jwt, public_key, algorithms=["ES256"], audience=expected_audience)

        # Validate nonce
        if decoded_vp["nonce"] != expected_nonce:
            raise Exception("Nonce mismatch!")

        # Decode the presentation_submission
        presentation_submission_encoded = presentation_response.get("presentation_submission")
        if not presentation_submission_encoded:
            raise Exception("Missing presentation_submission!")

        # Decode the URL-encoded presentation_submission
        presentation_submission = json.loads(urllib.parse.unquote(presentation_submission_encoded))

        # Validate the descriptor_map to ensure that the provided VC fulfills the request
        descriptor_map = presentation_submission.get("descriptor_map")
        if not descriptor_map or not isinstance(descriptor_map, list):
            raise Exception("Missing or invalid descriptor_map in presentation_submission!")

        for descriptor in descriptor_map:
            if descriptor.get("id") != "vc-presentation" or descriptor.get("format") != "jwt_vc":
                raise Exception("Invalid presentation_submission descriptor!")

        print("Verifiable Presentation and presentation_submission validated successfully!")
        return decoded_vp
    except jwt.exceptions.InvalidSignatureError as e:
        print(f"Invalid signature: {e}")
        return None
    except jwt.exceptions.InvalidAudienceError as e:
        print(f"Invalid audience: {e}")
        return None
    except Exception as e:
        print(f"Validation error: {e}")
        return None
