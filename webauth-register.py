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

from fido2.features import webauthn_json_mapping
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import AuthenticatorAttestationResponse, RegistrationResponse
from flask import Flask, render_template_string, request, session

webauthn_json_mapping.enabled = True

app = Flask(__name__)
app.secret_key = os.urandom(24)

# RP (Relying Party) Configuration
RP = {"id": "localhost", "name": "FidoLab Demo"}
server = Fido2Server(RP)

# In-memory "Database"
credentials = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>FIDO2/WebAuthn Demo</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 40px auto;">
    <h2>Feitian K40 WebAuthn Demo</h2>
    <div>
        <input type="text" id="username" placeholder="Username" value="ramon_test">
        <button onclick="register()">Register Key</button>
    </div>
    <pre id="log" style="background: #eee; padding: 10px; margin-top: 20px;"></pre>

    <script>
        const log = (m) => document.getElementById('log').innerText += m + '\\n';

        async function register() {
            const user = document.getElementById('username').value;
            const resp = await fetch('/get-options?user=' + user);
            const options = await resp.json();

            // Prepare options for the browser API
            options.publicKey.challenge = Uint8Array.from(atob(options.publicKey.challenge), c => c.charCodeAt(0));
            options.publicKey.user.id = Uint8Array.from(atob(options.publicKey.user.id), c => c.charCodeAt(0));

            log("Touching key for registration...");
            try {
                const cred = await navigator.credentials.create(options);

                // Helper to convert ArrayBuffer to Base64
                const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

                await fetch('/complete-registration', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        id: cred.id,
                        rawId: toBase64(cred.rawId),
                        response: {
                            attestationObject: toBase64(cred.response.attestationObject),
                            clientDataJSON: toBase64(cred.response.clientDataJSON)
                        },
                        type: cred.type
                    })
                });
                log("Registration Successful and Verified!");
            } catch (err) {
                log("Error: " + err.message);
            }
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
        {"id": user_id, "name": username, "displayName": username},
        credentials,
    )
    session["state"] = state

    # Properly serialize the binary data for JSON
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

    try:
        # These manual decodes ensure we have the correct 'bytes' type
        credential_id = base64.b64decode(data["rawId"] + "===")
        attestation_obj = base64.b64decode(
            data["response"]["attestationObject"] + "==="
        )
        client_data_json = base64.b64decode(data["response"]["clientDataJSON"] + "===")

        reg_response = RegistrationResponse(
            id=credential_id,
            response=AuthenticatorAttestationResponse(
                attestation_object=attestation_obj,
                client_data=client_data_json,
            ),
            authenticator_attachment=data.get("authenticatorAttachment"),
            type=data.get("type", "public-key"),
        )

        auth_data = server.register_complete(state, reg_response)
        credentials.append(auth_data.credential_data)

        print("✅ Successfully registered key!")
        return {"status": "OK"}

    except Exception as e:
        print(f"❌ Verification failed: {e}")
        import traceback

        traceback.print_exc()
        return {"status": "error", "message": str(e)}, 400


if __name__ == "__main__":
    app.run(host="localhost", port=5000)
