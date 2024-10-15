import issuer
import wallet
import verifier

# Step 1: Issue Verifiable Credentials (VC) for each schema
issuer.issue_vcs()

# Step 2: Create Verifiable Presentation (VP)
selected_claims = [
    "officialTravelDocExpiryDate",   # TravelAuth-specific claim
    "holdersName",                   # Common claim across VCs
    "issuerName",                    # Common claim across VCs
    "docNumberIdentifier",           # Common claim across VCs
    "placeOfIssueName",              # Common claim across VCs
    "birthdate"                      # Common claim across VCs
]

vp = wallet.create_verifiable_presentation(["travelAuth", "visa", "ePassport"], selected_claims)
print(f"Created Verifiable Presentation: {vp}")

# Step 3: Verify the Verifiable Presentation
verifier.verify_vp(vp, "travelAuth")
