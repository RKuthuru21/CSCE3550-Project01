from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
import os
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def _b64url_uint(i: int) -> str:
    b = i.to_bytes((i.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("utf-8")


@dataclass
class KeyPair:
    priv: rsa.RSAPrivateKey
    kid: str
    expiry: datetime  # UTC


class KeyStore:
    def __init__(self) -> None:
        self._keys: Dict[str, KeyPair] = {}

    def generate_key(self, expiry: datetime) -> str:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = base64.urlsafe_b64encode(os.urandom(12)).rstrip(b"=").decode("utf-8")
        self._keys[kid] = KeyPair(priv=priv, kid=kid, expiry=expiry)
        return kid

    def get_active_keys(self, now: Optional[datetime] = None) -> List[KeyPair]:
        now = now or datetime.now(timezone.utc)
        return [kp for kp in self._keys.values() if now < kp.expiry]

    def get_latest_active(self, now: Optional[datetime] = None) -> Optional[KeyPair]:
        active = self.get_active_keys(now)
        if not active:
            return None
        # pick the one that expires last
        return sorted(active, key=lambda k: k.expiry, reverse=True)[0]

    def get_any_expired(self, now: Optional[datetime] = None) -> Optional[KeyPair]:
        now = now or datetime.now(timezone.utc)
        for kp in self._keys.values():
            if now >= kp.expiry:
                return kp
        return None

    def find(self, kid: str) -> Optional[KeyPair]:
        return self._keys.get(kid)

    @staticmethod
    def priv_to_pem(priv: rsa.RSAPrivateKey) -> bytes:
        return priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def pub_to_pem(priv: rsa.RSAPrivateKey) -> bytes:
        pub = priv.public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def public_jwk(priv: rsa.RSAPrivateKey, kid: str) -> dict:
        pub = priv.public_key().public_numbers()
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": _b64url_uint(pub.n),
            "e": _b64url_uint(pub.e),
        }


# A single global keystore the app and tests can import
keystore = KeyStore()

def initialize_keys_for_demo() -> Tuple[str, str]:
    """
    Create one active key (expires in 10 minutes) and one expired key (expired 10 minutes ago).
    Return (active_kid, expired_kid).
    """
    now = datetime.now(timezone.utc)
    active_kid = keystore.generate_key(expiry=now + timedelta(minutes=10))
    expired_kid = keystore.generate_key(expiry=now - timedelta(minutes=10))
    return active_kid, expired_kid
