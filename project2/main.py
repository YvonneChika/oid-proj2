# import verifier
# import wallet
# import json
# import time

# # Simulate network communication with logging
# def log_network_message(message, method="POST"):
#     print(f"\n[Network Message - {method}] {message}")
#     time.sleep(1)  # Simulate slight network delay

# # Step 1: Verifier sends a Presentation Request to the Wallet
# presentation_request = verifier.create_verifier_request()
# log_network_message(f"Verifier sends Presentation Request to Wallet: {json.dumps(presentation_request, indent=2)}", method="POST")

# # Step 2: Wallet prepares a Verifiable Presentation based on the received request
# log_network_message("Wallet prepares Verifiable Presentation (VP).", method="POST")
# vp_token = wallet.create_verifiable_presentation()
# log_network_message(f"Wallet sends Verifiable Presentation to Verifier: {vp_token}", method="POST")

# # Step 3: Verifier validates the received Verifiable Presentation
# log_network_message("Verifier validates the received Verifiable Presentation.", method="POST")
# verifier.validate_presentation(vp_token, 'keys/travelAuth_public.pem', "unique_nonce_value", "https://verifier.example.com")

import verifier
import wallet
import json
import time

# Simulate network communication with logging
def log_network_message(message, method="POST"):
    print(f"\n[Network Message - {method}] {message}")
    time.sleep(1)  # Simulate slight network delay

# Step 1: Verifier sends Authorization Request via Deeplink
deeplink = verifier.generate_deeplink()
log_network_message(f"Verifier Authorization request sent to the Wallet via deeplink: {deeplink}", method="POST")

# Step 2: Wallet retrieves the request URI from the deeplink
log_network_message(f"Wallet retrieves the request URI: {deeplink}", method="GET")

# Step 3: Verifier sends the Presentation Request (Presentation Definition) to the Wallet
presentation_request, nonce = verifier.create_presentation_request()
log_network_message(f"Verifier sends Presentation Request to Wallet: {json.dumps(presentation_request, indent=2)}", method="POST")

# Step 4: Wallet authenticates and provides consent
log_network_message("Wallet authenticates and provides consent to the request.", method="POST")

# Step 5: Wallet prepares a Verifiable Presentation (VP) based on the received request
log_network_message("Wallet prepares Verifiable Presentation (VP).", method="POST")
vp_token, nonce = wallet.create_verifiable_presentation()  # Wallet generates VP with auto-generated nonce
log_network_message(f"Wallet sends Verifiable Presentation response: {vp_token}", method="POST")

# Step 6: Verifier validates the received Verifiable Presentation using the generated nonce
log_network_message("Verifier validates the received Verifiable Presentation.", method="POST")
verifier.validate_presentation(vp_token, 'keys/travelAuth_public.pem', nonce, "https://verifier.example.com")
