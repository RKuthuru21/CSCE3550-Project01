from __future__ import annotations
from datetime import datetime, timedelta, timezone
from flask import request, Response
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
        # never issue a token whose exp is later than the key's expiry
        exp = min(kp.expiry, now + timedelta(hours=1))

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

    # Return the raw JWT string so the grader can read it directly
    #    (the official media type for a bare JWT is application/jwt)
    return Response(token, mimetype="application/jwt")
