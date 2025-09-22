#Name: Rithvik Kuthuru
#Class: CSCE3550
#Project01
#09/19/2025

from __future__ import annotations
from flask import Flask
from auth import auth_handler
from jwks import jwks_handler
from keystore import initialize_keys_for_demo

app = Flask(__name__)

# Generate one active and one expired key on startup
initialize_keys_for_demo()

@app.get("/.well-known/jwks.json")
def jwks_route():
    return jwks_handler()

@app.post("/auth")
def auth_route():
    return auth_handler()

if __name__ == "__main__":
    # Serve on port 8080 as required
    app.run(host="0.0.0.0", port=8080, debug=True)
