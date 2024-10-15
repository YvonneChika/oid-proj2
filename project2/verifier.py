import jwt
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "VC_keys"

# Function to load the public key
def load_public_key(vc_name):
    with open(f"{KEYS_DIR}/{vc_name}_public.pem", "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

# Function to verify the Verifiable Presentation (VP)
def verify_vp(vp_token, vc_name):
    public_key = load_public_key(vc_name)

    try:
        # Decode and verify the VP using SD-JWT and the public key
        decoded_vp = jwt.decode(vp_token, public_key, algorithms=["ES256"])
        print("Verifiable Presentation successfully verified.")
        print(f"Disclosed claims: {decoded_vp['vp']['sd_digests']}")
    except jwt.exceptions.InvalidSignatureError:
        print("Invalid signature!")
    except jwt.exceptions.ExpiredSignatureError:
        print("VP has expired!")
    except Exception as e:
        print(f"Verification error: {e}")

# Example usage: Verifying the Verifiable Presentation
vp = "paste_the_signed_vp_here"
verify_vp(vp, "travelAuth")
