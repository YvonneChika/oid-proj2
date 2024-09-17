import verifier
import wallet
import json
import time
import oid4vc_issuer

# Simulate network communication with logging
def log_network_message(message, method="POST"):
    print(f"\n[Network Message - {method}] {message}")
    time.sleep(1)  # Simulate slight network delay

# Step 1: Verifier Authorization request sent to the Wallet via request URI
verifier_request_uri = "https://wallet.example.com/presentation-request?request_uri=abc123"
log_network_message(f"Verifier Authorization request sent to the Wallet via request URI: {verifier_request_uri}", method="POST")

# Step 2: Wallet retrieves the Verifier Authorization request
log_network_message("Wallet retrieves the authorization request from the Verifier via request URI.", method="GET")

# Step 3: Verifier sends Presentation Request (Presentation Definition) to the Wallet
verifier_request, nonce = verifier.create_verifier_request()  # Generates dynamic nonce
log_network_message(f"Verifier sends Presentation Request to Wallet: {json.dumps(verifier_request, indent=2)}", method="POST")

# Step 4: Wallet authenticates and provides consent
log_network_message("Wallet authenticates and provides consent to the request.", method="POST")

# Step 5: Wallet prepares Verifiable Presentation based on the received request
log_network_message("Wallet prepares Verifiable Presentation (VP) based on received request.", method="POST")

# Step 6: Wallet generates Verifiable Credential using issuer logic
vc, claims = oid4vc_issuer.create_digital_travel_authorization_vc()
signed_vc = oid4vc_issuer.sign_vc(vc, oid4vc_issuer.private_key)

# Step 7: Wallet sends the Verifiable Presentation (VP) response (VP token with SD-JWT Verifiable Credential & Presentation Submission)
vp_with_proof = wallet.create_verifiable_presentation(signed_vc, nonce, verifier_request["aud"])
log_network_message(f"Wallet sends Verifiable Presentation response with VP token, SD-JWT Verifiable Credential, and encoded presentation_submission: {json.dumps(vp_with_proof, indent=2)}", method="POST")

# Ensure vp_with_proof is a dictionary before passing to verifier.validate_presentation
if isinstance(vp_with_proof, dict):
    # Step 8: Verifier validates the received Verifiable Presentation
    log_network_message("Verifier validates the received Verifiable Presentation.", method="POST")
    verifier.validate_presentation(vp_with_proof, nonce, verifier_request["aud"])
else:
    log_network_message("Validation error: Invalid presentation_response format, expected dictionary.", method="ERROR")
