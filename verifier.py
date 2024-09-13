import json
import jwt
from jwt.exceptions import InvalidSignatureError
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Verifier's endpoint to receive and validate VP
@app.route("/verify", methods=["POST"])
def verify_vp():
    vp_jwt = request.data.decode("utf-8")  # Get the VP (JWT format)

    # Load the public key that corresponds to the wallet's private key
    public_key_pem = b"""-----BEGIN PUBLIC KEY-----
    (INSERT WALLET'S PUBLIC KEY PEM HERE)
    -----END PUBLIC KEY-----"""
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    try:
        # Decode and verify the SD-JWT
        decoded_vp = jwt.decode(vp_jwt, public_key, algorithms=["ES256"])
        print("Verifiable Presentation decoded and verified!")
        return jsonify({"status": "verified", "vp": decoded_vp}), 200
    except InvalidSignatureError:
        return jsonify({"status": "error", "message": "Invalid signature"}), 400

if __name__ == "__main__":
    # Run the Verifier server
    app.run(port=5000)
