#!/usr/bin/env uv run
# /// script
# dependencies = [
#     "flask",
#     "fido2>=1.1.0",
# ]
# ///

import base64
import json
import os
import pickle  # To serialize the AttestedCredentialData object
import sqlite3

from fido2.features import webauthn_json_mapping
from fido2.server import Fido2Server
from fido2.webauthn import AuthenticatorAttestationResponse, RegistrationResponse
from flask import Flask, render_template_string, request, session

webauthn_json_mapping.enabled = True

app = Flask(__name__)
app.secret_key = os.urandom(24)

# RP (Relying Party) Configuration
RP = {"id": "localhost", "name": "FidoLab Demo"}
server = Fido2Server(RP)

# --- SQLite Setup ---
DB_FILE = "fido2_lab.db"


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                credential_id BLOB NOT NULL,
                public_key BLOB NOT NULL
            )
        """)


init_db()


@app.route("/")
def index():
    # Load from file every time so you can edit register.html
    # and just refresh the page to see changes.
    try:
        with open("register.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h2>Error: register.html not found</h2>", 404


@app.route("/get-options")
def get_options():
    username = request.args.get("user", "default_user")
    session["username"] = username
    user_id = os.urandom(16)

    # We start with an empty list because we allow multiple keys per user in a real app,
    # but for this lab, we just need to generate the challenge.
    registration_data, state = server.register_begin(
        {"id": user_id, "name": username, "displayName": username}, []
    )
    session["state"] = state

    return {
        "publicKey": {
            "rp": registration_data.public_key.rp,
            "user": {
                "id": base64.b64encode(registration_data.public_key.user.id).decode(),
                "name": registration_data.public_key.user.name,
                "displayName": registration_data.public_key.user.display_name,
            },
            "challenge": base64.b64encode(
                registration_data.public_key.challenge
            ).decode(),
            "pubKeyCredParams": registration_data.public_key.pub_key_cred_params,
            "timeout": registration_data.public_key.timeout,
            "attestation": registration_data.public_key.attestation,
        }
    }


@app.route("/complete-registration", methods=["POST"])
def complete_registration():
    data = request.json
    state = session.get("state")
    username = session.get("username")

    try:
        credential_id_raw = base64.b64decode(data["rawId"] + "===")
        attestation_obj = base64.b64decode(
            data["response"]["attestationObject"] + "==="
        )
        client_data_json = base64.b64decode(data["response"]["clientDataJSON"] + "===")

        reg_response = RegistrationResponse(
            id=credential_id_raw,
            response=AuthenticatorAttestationResponse(
                attestation_object=attestation_obj,
                client_data=client_data_json,
            ),
            type=data.get("type", "public-key"),
        )

        auth_data = server.register_complete(state, reg_response)

        # --- Save to SQLite ---
        # We pickle the credential_data object to save it easily as a BLOB
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                "INSERT INTO credentials (username, credential_id, public_key) VALUES (?, ?, ?)",
                (
                    username,
                    auth_data.credential_data.credential_id,
                    pickle.dumps(auth_data.credential_data),
                ),
            )

        print(f"✅ Registered & Persisted key for {username}")
        return {"status": "OK"}

    except Exception as e:
        print(f"❌ Verification failed: {e}")
        return {"status": "error", "message": str(e)}, 400


if __name__ == "__main__":
    app.run(host="localhost", port=5001)
