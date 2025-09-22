from __future__ import annotations
from flask import jsonify
from datetime import datetime, timezone
from keystore import keystore, KeyStore


def jwks_handler():
    # Only return unexpired public keys
    active = keystore.get_active_keys(datetime.now(timezone.utc))
    keys = [KeyStore.public_jwk(kp.priv, kp.kid) for kp in active]
    return jsonify({"keys": keys})
