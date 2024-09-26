import verifier
import wallet
import json
import time

# Simulate network communication with logging
def log_network_message(message, method="POST"):
    print(f"\n[Network Message - {method}] {message}")
    time.sleep(1)  # Simulate slight network delay

# Step 1: Verifier sends a Presentation Request to the Wallet
presentation_request = verifier.create_verifier_request()
log_network_message(f"Verifier sends Presentation Request to Wallet: {json.dumps(presentation_request, indent=2)}", method="POST")

# Step 2: Wallet prepares a Verifiable Presentation based on the received request
log_network_message("Wallet prepares Verifiable Presentation (VP).", method="POST")
vp_token = wallet.create_verifiable_presentation()
log_network_message(f"Wallet sends Verifiable Presentation to Verifier: {vp_token}", method="POST")

# Step 3: Verifier validates the received Verifiable Presentation
log_network_message("Verifier validates the received Verifiable Presentation.", method="POST")
verifier.validate_presentation(vp_token, 'keys/travelAuth_public.pem', "unique_nonce_value", "https://verifier.example.com")
