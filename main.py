from wallet import Wallet
from verifier import Verifier
import json

# Load the Verifiable Credential (VC)
with open('VC.json', 'r') as f:
    vc = json.load(f)

# Initialize Wallet and Verifier
wallet = Wallet(vc)
verifier = Verifier()

# Log for network messages
network_messages = []

# Step 1: Verifier sends Authorization request to Wallet
auth_request = verifier.send_authorization_request()
network_messages.append({
    "step": "Verifier sends Authorization Request",
    "message": auth_request
})

# Step 2: Wallet retrieves Authorization request
auth_retrieved = wallet.retrieve_authorization_request(auth_request)
network_messages.append({
    "step": "Wallet retrieves Authorization Request",
    "message": auth_retrieved
})

# Step 3: Verifier sends Presentation Request to Wallet
presentation_request = verifier.send_presentation_request(auth_retrieved)
network_messages.append({
    "step": "Verifier sends Presentation Request",
    "message": presentation_request
})

# Step 4: Wallet authenticates and provides consent
wallet_consent = wallet.authenticate_and_consent(presentation_request)
network_messages.append({
    "step": "Wallet authenticates and provides consent",
    "message": wallet_consent
})

# Step 5: Wallet sends Presentation Response (VP Token with SD-JWT Verifiable Credential)
vp_response = wallet.send_presentation_response()
network_messages.append({
    "step": "Wallet sends Presentation Response",
    "message": vp_response
})

# Step 6: Verifier verifies the presentation
verification_result = verifier.verify_presentation(vp_response)
network_messages.append({
    "step": "Verifier verifies Presentation Response",
    "result": verification_result
})

# Output verification result
print("Verification result:", verification_result)

# Save network messages to a JSON file
with open("network_messages.json", "w") as f:
    json.dump(network_messages, f, indent=4)

print("Network messages have been saved to 'network_messages.json'")
