from __future__ import annotations
from datetime import datetime, timezone
import jwt
import json

from main import app
from keystore import keystore, KeyStore


def test_jwks_only_unexpired_keys():
    client = app.test_client()
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "keys" in data
    # keystore initializes 1 active and 1 expired; JWKS must expose only active
    assert len(data["keys"]) == 1
    jwk = data["keys"][0]
    assert jwk["kty"] == "RSA"
    assert jwk["alg"] == "RS256"
    assert jwk["use"] == "sig"
    assert "kid" in jwk and "n" in jwk and "e" in jwk

def _decode_with_store(token: str):
    # Inspect header to choose the right public key
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    kp = keystore.find(kid)
    assert kp is not None
    pem_pub = KeyStore.pub_to_pem(kp.priv)
    return jwt.decode(token, pem_pub, algorithms=["RS256"])

def test_auth_valid_token_uses_active_key_and_future_exp():
    client = app.test_client()
    resp = client.post("/auth")
    assert resp.status_code == 200
    tok = resp.get_json()["token"]
    decoded = _decode_with_store(tok)
    assert decoded["iss"] == "jwks-server"
    assert decoded["sub"] == "fake-user"
    assert decoded["exp"] > int(datetime.now(timezone.utc).timestamp())

def test_auth_expired_param_returns_expired_token_signed_by_expired_key():
    client = app.test_client()
    resp = client.post("/auth?expired=1")
    assert resp.status_code == 200
    tok = resp.get_json()["token"]

    # Verify signature but expect expiration failure when validating with options
    headers = jwt.get_unverified_header(tok)
    kid = headers["kid"]
    kp = keystore.find(kid)
    # Ensure we actually used an expired key
    assert kp is not None and datetime.now(timezone.utc) >= kp.expiry

    pem_pub = KeyStore.pub_to_pem(kp.priv)

    try:
        jwt.decode(tok, pem_pub, algorithms=["RS256"])
        assert False, "expected expired token to raise"
    except jwt.ExpiredSignatureError:
        pass  # expected
