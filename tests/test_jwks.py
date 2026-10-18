"""Asymmetric (ES256) Supabase signing-key verification via JWKS.

Covers the new-Supabase-project case: access tokens are signed with an
EC P-256 signing key, so the legacy HS256 shared-secret path in
``verify_dashboard_token`` can never verify them. The public halves are
served by the project JWKS endpoint, which these tests fake locally.
"""

from __future__ import annotations

import base64
import datetime

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from uuid_utils import uuid7

from relay.api import jwks
from relay.api.account import AccountError, verify_dashboard_token
from relay.config import settings
from tests.conftest import mint_test_jwt

# One EC P-256 keypair stands in for the project's signing key.
EC_KEY = ec.generate_private_key(ec.SECP256R1())
KID = "test-es256-kid-1"
OTHER_KID = "test-es256-kid-rotated"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ec_jwk(kid: str = KID) -> dict:
    nums = EC_KEY.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": kid,
        "x": _b64u(nums.x.to_bytes(32, "big")),
        "y": _b64u(nums.y.to_bytes(32, "big")),
    }


def mint_es256_token(
    sub: str,
    exp_minutes: int = 60,
    kid: str = KID,
    iss: str | None = None,
    key=EC_KEY,
) -> str:
    issuer = iss or f"{settings.supabase_url.rstrip('/')}/auth/v1"
    now = datetime.datetime.now(datetime.UTC)
    payload = {
        "sub": sub,
        "iss": issuer,
        "aud": "authenticated",  # mimic real production tokens (Task 20)
        "exp": int((now + datetime.timedelta(minutes=exp_minutes)).timestamp()),
        "iat": int(now.timestamp()),
        "email": f"{sub}@example.com",
    }
    return pyjwt.encode(payload, key, algorithm="ES256", headers={"kid": kid})


@pytest.fixture
def fake_jwks(monkeypatch):
    """Serve a local JWKS document; count fetches to prove caching."""
    jwks.clear_cache()
    doc = {"keys": [_ec_jwk(KID), _ec_jwk(OTHER_KID)]}
    calls = {"n": 0}

    def fake(url: str) -> dict:
        calls["n"] += 1
        return doc

    monkeypatch.setattr(jwks, "_fetch_jwks_document", fake)
    yield calls
    jwks.clear_cache()


# ---------------------------------------------------------------------------
# Direct function-level verification (no DB required)
# ---------------------------------------------------------------------------


def test_es256_valid_token_verifies(fake_jwks):
    claims = verify_dashboard_token(mint_es256_token("user-es256"))
    assert claims["sub"] == "user-es256"
    assert claims["iss"] == f"{settings.supabase_url.rstrip('/')}/auth/v1"


def test_es256_unknown_kid_rejected(fake_jwks):
    with pytest.raises(AccountError) as ei:
        verify_dashboard_token(mint_es256_token("user-es256", kid="no-such-kid"))
    assert ei.value.status_code == 401
    assert ei.value.code == "UNAUTHORIZED"
    assert "Invalid or expired" in ei.value.message


def test_es256_tampered_payload_rejected(fake_jwks):
    token = mint_es256_token("user-es256")
    head, _, sig = token.split(".")
    # Keep the real header/signature, swap the payload for a forged one.
    forged = _b64u(b'{"sub":"attacker","iss":"x","exp":9999999999}')
    with pytest.raises(AccountError):
        verify_dashboard_token(f"{head}.{forged}.{sig}")


def test_es256_expired_rejected(fake_jwks):
    with pytest.raises(AccountError):
        verify_dashboard_token(mint_es256_token("user-es256", exp_minutes=-10))


def test_es256_wrong_issuer_rejected(fake_jwks):
    with pytest.raises(AccountError):
        verify_dashboard_token(
            mint_es256_token("user-es256", iss="https://wrong-issuer.com/auth/v1")
        )


def test_es256_missing_kid_rejected(fake_jwks):
    """A token header without kid: the JWKS lookup is impossible, must 401."""
    token = mint_es256_token("user-es256")
    _head, payload, sig = token.split(".")
    header_without_kid = _b64u(b'{"alg":"ES256","typ":"JWT"}')
    with pytest.raises(AccountError) as ei:
        verify_dashboard_token(f"{header_without_kid}.{payload}.{sig}")
    assert ei.value.code == "UNAUTHORIZED"


def test_es256_jwks_fetch_failure_is_401_not_500(monkeypatch):
    jwks.clear_cache()

    def broken(url: str) -> dict:
        raise OSError("network unreachable")

    monkeypatch.setattr(jwks, "_fetch_jwks_document", broken)
    try:
        with pytest.raises(AccountError) as ei:
            verify_dashboard_token(mint_es256_token("user-es256"))
        assert ei.value.status_code == 401
    finally:
        jwks.clear_cache()


def test_unsupported_alg_rejected():
    # Hand-built token: header claims HS512 (neither HS256 nor asymmetric).
    header = _b64u(b'{"alg":"HS512","typ":"JWT"}')
    payload = _b64u(b'{"sub":"u","iss":"i","exp":9999999999}')
    sig = _b64u(b"garbage-signature")
    with pytest.raises(AccountError) as ei:
        verify_dashboard_token(f"{header}.{payload}.{sig}")
    assert "Unsupported token algorithm" in ei.value.message


def test_hs256_path_unchanged(fake_jwks):
    """The legacy shared-secret branch still works after the dispatch split."""
    claims = verify_dashboard_token(mint_test_jwt("user-hs256"))
    assert claims["sub"] == "user-hs256"


# ---------------------------------------------------------------------------
# End-to-end: ES256 token on a real account route (needs DB)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_rest_rate_limits():
    """Disable slowapi limits during test suite (mirrors test_account.py)."""
    from relay.ratelimit import limiter

    limiter.enabled = False
    yield
    limiter.enabled = True


async def test_es256_token_with_aud_claim_verifies(fake_jwks):
    """Regression (Task 20): real tokens carry an aud claim; production saw
    'Invalid audience' because decode had no audience configured. The relay
    must verify signature/issuer/expiry while tolerating any aud value."""
    # mint_es256_token includes aud='authenticated' since Task 20.
    claims = verify_dashboard_token(mint_es256_token("user-aud"))
    assert claims["sub"] == "user-aud"
    assert claims.get("aud") == "authenticated"


async def test_es256_end_to_end_account_agents(client, db, fake_jwks):
    """The exact production wire: ES256 bearer token on GET /v1/account/agents."""
    token = mint_es256_token(str(uuid7()))
    r1 = await client.get("/v1/account/agents", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200
    assert r1.json() == {"agents": []}

    # Second request must be served from cache: no additional JWKS fetch.
    r2 = await client.get("/v1/account/agents", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    assert fake_jwks["n"] == 1
