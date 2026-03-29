#!/usr/bin/env uv run
# /// script
# dependencies = [
#     "flask",
#     "fido2>=1.1.0",
# ]
# ///

import base64
import os
import pickle
import sqlite3

from fido2.features import webauthn_json_mapping
from fido2.server import Fido2Server
from fido2.webauthn import AuthenticationResponse, AuthenticatorAssertionResponse
from flask import Flask, request, session

# Enable fido2's automatic JSON mapping for WebAuthn types
webauthn_json_mapping.enabled = True

app = Flask(__name__)
app.secret_key = os.urandom(24)

RP = {"id": "localhost", "name": "FidoLab Demo"}
server = Fido2Server(RP)
DB_FILE = "fido2_lab.db"


def get_user_credentials(username):
    credentials = []
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.execute(
            "SELECT public_key FROM credentials WHERE username = ?", (username,)
        )
        for row in cursor:
            # Unpickle the AttestedCredentialData object saved during registration
            credentials.append(pickle.loads(row[0]))
    return credentials


@app.route("/")
def index():
    try:
        with open("login.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>login.html not found</h1>"


@app.route("/get-assertion-options")
def get_assertion_options():
    username = request.args.get("user")
    credentials = get_user_credentials(username)

    if not credentials:
        return {
            "status": "error",
            "message": "User not found or no keys registered",
        }, 404

    options, state = server.authenticate_begin(credentials)

    # Store state in session
    session["state"] = state
    session["allowed_credentials"] = [pickle.dumps(c) for c in credentials]

    pub_key_opts = options.public_key

    # Explicitly map the properties and Base64 encode the bytes.
    pub_key = {
        "challenge": base64.b64encode(pub_key_opts.challenge).decode("utf-8"),
        "timeout": pub_key_opts.timeout,
        "rpId": pub_key_opts.rp_id,
        "userVerification": "preferred",
        "allowCredentials": [
            {
                "type": "public-key",
                "id": base64.b64encode(cred.id).decode("utf-8"),
            }
            for cred in pub_key_opts.allow_credentials
        ]
        if pub_key_opts.allow_credentials
        else [],
    }

    return {"publicKey": pub_key}


@app.route("/complete-assertion", methods=["POST"])
def complete_assertion():
    data = request.json
    state = session.get("state")
    allowed_creds_pickled = session.get("allowed_credentials", [])

    if not state or not allowed_creds_pickled:
        return {"status": "error", "message": "Session expired"}, 400

    try:
        credentials = [pickle.loads(c) for c in allowed_creds_pickled]

        # 1. Decode incoming Base64 strings to bytes
        credential_id = base64.b64decode(data["rawId"] + "===")
        auth_data = base64.b64decode(data["response"]["authenticatorData"] + "===")
        client_data_json = base64.b64decode(data["response"]["clientDataJSON"] + "===")
        signature = base64.b64decode(data["response"]["signature"] + "===")

        user_handle_b64 = data["response"].get("userHandle")
        user_handle = (
            base64.b64decode(user_handle_b64 + "===") if user_handle_b64 else None
        )

        # 2. Package into fido2 1.x response objects
        auth_response = AuthenticationResponse(
            id=credential_id,
            type=data.get("type", "public-key"),
            response=AuthenticatorAssertionResponse(
                authenticator_data=auth_data,
                client_data=client_data_json,
                signature=signature,
                user_handle=user_handle,
            ),
        )

        # 3. Verify using the server's authenticate_complete method
        server.authenticate_complete(state, credentials, auth_response)

        print("✅ Successful authentication for user!")
        return {"status": "OK"}

    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return {"status": "error", "message": str(e)}, 400


if __name__ == "__main__":
    app.run(host="localhost", port=5002, debug=True)
