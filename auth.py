from __future__ import annotations
from datetime import datetime, timedelta, timezone
from flask import request, jsonify
import jwt
from keystore import keystore, KeyStore


def auth_handler():
    """
    POST /auth
    If query param 'expired' is present (any truthy value), issue a token signed by an expired key
    and set exp in the past. Otherwise use an active key with exp in the future.
    """
    expired_param = request.args.get("expired", "").lower()
    want_expired = expired_param in {"1", "true", "yes"}

    now = datetime.now(timezone.utc)

    if want_expired:
        kp = keystore.get_any_expired(now)
        if kp is None:
            return ("no expired key available", 503)
        exp = now - timedelta(hours=1)
    else:
        kp = keystore.get_latest_active(now)
        if kp is None:
            return ("no active signing key", 503)
        exp = min(kp.expiry, now + timedelta(hours=1))  # do not extend past key expiry

    pem_priv = KeyStore.priv_to_pem(kp.priv)

    claims = {
        "iss": "jwks-server",
        "sub": "fake-user",
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(
        payload=claims,
        key=pem_priv,
        algorithm="RS256",
        headers={"kid": kp.kid},
    )

    # Test client often expects JSON
    return jsonify({"token": token})
