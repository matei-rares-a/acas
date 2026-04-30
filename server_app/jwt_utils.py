"""
JWT key management and encode/decode helpers.

Covers requirements §4 (Ed25519, iss/aud/jti/exp), §5 (persistent keys, kid rotation).

Key persistence strategy:
  1. Look for PEM files at JWT_KEY_DIR (env var, default: server_app/keys/).
  2. If not found, generate a new Ed25519 pair and persist it.
  3. Private key is never exposed via any endpoint.
  4. Public keys are served at /jwks.json for client verification.
"""

import base64
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

# ---------------------------------------------------------------------------
# Claims / audience constants
# ---------------------------------------------------------------------------
JWT_ISSUER   = "acas-schnorr-server"
JWT_AUDIENCE = "acas-client"
JWT_TTL_S    = 3600   # 1 hour

# Current signing kid — increment when rotating
_KID = "kid-1"

# ---------------------------------------------------------------------------
# Key loading / generation  §5
# ---------------------------------------------------------------------------
_KEY_DIR       = Path(os.environ.get("JWT_KEY_DIR", Path(__file__).parent / "keys"))
_PRIV_PEM_PATH = _KEY_DIR / "jwt_ed25519_priv.pem"
_PUB_PEM_PATH  = _KEY_DIR / "jwt_ed25519_pub.pem"


def _load_or_generate_keys() -> tuple[bytes, bytes]:
    """Load Ed25519 PEM key pair from disk, generating and persisting if absent."""
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    if _PRIV_PEM_PATH.exists() and _PUB_PEM_PATH.exists():
        priv_pem = _PRIV_PEM_PATH.read_bytes()
        pub_pem  = _PUB_PEM_PATH.read_bytes()
        # Validate by loading both
        load_pem_private_key(priv_pem, password=None)
        load_pem_public_key(pub_pem)
        print(f"[jwt_utils] Loaded Ed25519 key pair from {_KEY_DIR}")
    else:
        priv_obj = Ed25519PrivateKey.generate()
        priv_pem = priv_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        pub_pem  = priv_obj.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        _PRIV_PEM_PATH.write_bytes(priv_pem)
        _PUB_PEM_PATH.write_bytes(pub_pem)
        print(f"[jwt_utils] Generated new Ed25519 key pair → {_KEY_DIR}")
    return priv_pem, pub_pem


_PRIV_PEM, _PUB_PEM = _load_or_generate_keys()

# Public key registry — supports rotation by adding new entries: {kid: pub_pem_bytes}
PUBLIC_KEYS: dict[str, bytes] = {_KID: _PUB_PEM}


# ---------------------------------------------------------------------------
# Encode / Decode  §4
# ---------------------------------------------------------------------------
def jwt_encode(extra_claims: dict) -> str:
    """Sign with Ed25519.  Always emits: iss, aud, iat, exp, jti, kid header."""
    now = datetime.now(timezone.utc)
    claims = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=JWT_TTL_S),
        "jti": secrets.token_urlsafe(16),
        **extra_claims,
    }
    return jwt.encode(
        claims,
        _PRIV_PEM,
        algorithm="EdDSA",
        headers={"kid": _KID},
    )


def jwt_decode(token: str) -> dict:
    """Fully validate a JWT.  Raises jwt.InvalidTokenError on any failure.

    Validates: signature, algorithm, iss, aud, iat, exp, jti presence, kid.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as exc:
        raise jwt.InvalidTokenError("malformed token header") from exc
    kid = header.get("kid", _KID)
    pub = PUBLIC_KEYS.get(kid)
    if pub is None:
        raise jwt.InvalidTokenError("unknown kid")
    return jwt.decode(
        token,
        pub,
        algorithms=["EdDSA"],
        options={"require": ["iss", "aud", "iat", "exp", "jti"]},
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )


# ---------------------------------------------------------------------------
# JWKS payload for /jwks.json  §4.5
# ---------------------------------------------------------------------------
def jwks_payload() -> dict:
    """Build RFC 7517 JWKS payload for all registered public keys."""
    keys = []
    for kid, pub_pem in PUBLIC_KEYS.items():
        pub_obj = load_pem_public_key(pub_pem)
        raw = pub_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)
        keys.append({
            "kid": kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "x":   base64.urlsafe_b64encode(raw).rstrip(b"=").decode(),
        })
    return {"keys": keys}
