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

from fido2.client import ClientData
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)
from flask import Flask, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Conceptual Configuration ---
# RP = Relying Party (Your App)
RP = {"id": "localhost", "name": "Feitian Demo App"}
server = Fido2Server(RP)

# In-memory "Database"
# In a real app, you'd store 'credentials' in DuckDB or PostgreSQL
users = {}  # username -> user_dict
credentials = []  # List of registered credentials

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>FIDO2/WebAuthn Demo</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h2>Feitian K40 WebAuthn Demo</h2>
    <div>
        <input type="text" id="username" placeholder="Username" value="ramon_test">
        <button onclick="register()">Register Key</button>
        <button onclick="login()">Authenticate</button>
    </div>
    <pre id="log" style="background: #eee; padding: 10px; margin-top: 20px;"></pre>

    <script>
        const log = (m) => document.getElementById('log').innerText += m + '\\n';

        async function register() {
            const user = document.getElementById('username').value;
            const resp = await fetch('/get-options?user=' + user);
            const options = await resp.json();

            // Convert base64 back to binary for the browser API
            options.publicKey.challenge = Uint8Array.from(atob(options.publicKey.challenge), c => c.charCodeAt(0));
            options.publicKey.user.id = Uint8Array.from(atob(options.publicKey.user.id), c => c.charCodeAt(0));

            log("Touching key for registration...");
            const cred = await navigator.credentials.create(options);

            // Send the result back to the server
            await fetch('/complete-registration', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    id: cred.id,
                    rawId: btoa(String.fromCharCode(...new Uint8Array(cred.rawId))),
                    response: {
                        attestationObject: btoa(String.fromCharCode(...new Uint8Array(cred.response.attestationObject))),
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(cred.response.clientDataJSON)))
                    },
                    type: cred.type
                })
            });
            log("Registration Successful!");
        }
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/get-options")
def get_options():
    username = request.args.get("user", "default_user")
    user_id = os.urandom(16)

    registration_data, state = server.register_begin(
        {
            "id": user_id,
            "name": username,
            "displayName": username,
        },
        credentials,
    )

    session["state"] = state

    # Manually build the JSON-compatible dictionary
    # The browser's WebAuthn API expects specific fields to be base64 encoded
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

    # Verify the registration with the fido2 server
    auth_data = server.register_complete(state, data)

    # Store the credential in your 'database'
    credentials.append(auth_data.credential_data)

    print(f"Successfully registered key for user!")
    return {"status": "OK"}


if __name__ == "__main__":
    print("🚀 Starting Demo at http://localhost:5000")
    app.run(port=5000)
