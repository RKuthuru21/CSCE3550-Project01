# CSCE3550 Project01
A basic RESTful JWKS server

# Basic JWKS Server (Flask, PyJWT, cryptography)

Serve JWKS and issue JWTs with active and expired key paths.

## Endpoints
- `GET /.well-known/jwks.json` returns only **unexpired** RSA public keys in JWKS format.
- `POST /auth` returns a valid JWT signed by an **active** key.
- `POST /auth?expired=1` returns a JWT signed by an **expired** key and with an **expired** `exp`.

## Run

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
